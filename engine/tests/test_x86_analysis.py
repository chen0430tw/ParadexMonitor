"""Regression tests for x86 and x64 decoding, IAT resolution and arguments."""
import struct
import unittest
import io
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from ppm_engine.architecture import pe_bitness
from ppm_engine.topology.callgraph import CallGraph
from ppm_engine.topology.dataflow import track_arguments
from ppm_engine.reconstruct.pseudo import PseudoCodeGenerator
from ppm_engine.patterns.xor_payload import XorPayloadPattern


class Adapter:
    def __init__(self, code, bits=32, image_base=0x400000):
        self.code = code
        self._raw = code
        self.section = SimpleNamespace(
            VirtualAddress=0x1000, PointerToRawData=0,
            SizeOfRawData=len(code), Characteristics=0x60000020,
            Name=b'.text\0\0\0', get_data=lambda: code)
        self._pe = SimpleNamespace(
            FILE_HEADER=SimpleNamespace(Machine=0x14C if bits == 32 else 0x8664),
            OPTIONAL_HEADER=SimpleNamespace(
                Magic=0x10B if bits == 32 else 0x20B, ImageBase=image_base),
            sections=[self.section], parse_data_directories=lambda **kwargs: None)

    def _find_section(self, name):
        return self.section

    def _build_iat_map(self):
        return {0x2000: ('KERNEL32.dll', 'GetProcAddress')}

    def entry_point(self):
        return 0x1000


def x86_call(prefix=b'', base=0x400000):
    return prefix + b'\xff\x15' + struct.pack('<I', base + 0x2000) + b'\xc3'


class ArchitectureTests(unittest.TestCase):
    def test_pseudo_cli_skips_strings_outside_mapped_sections(self):
        from ppm_engine.cli import _cmd_pseudo
        adapter = Adapter(x86_call())
        adapter.strings = lambda **kwargs: [{'rva': 99999, 'value': 'overlay'}]
        adapter._pe.get_rva_from_offset = lambda offset: None
        stream = io.StringIO()
        with patch('ppm_engine.cli._make_adapter', return_value=adapter), redirect_stdout(stream):
            _cmd_pseudo(SimpleNamespace(file='sample.exe', rva='0x1000'))
        self.assertIn('GetProcAddress', stream.getvalue())

    def test_rejects_arm_instead_of_decoding_as_x86(self):
        adapter = Adapter(b'\xc3')
        adapter._pe.FILE_HEADER.Machine = 0xAA64
        with self.assertRaises(ValueError):
            pe_bitness(adapter._pe)

    def test_x86_absolute_iat_above_signed_address_range(self):
        base = 0xF0000000
        graph = CallGraph.from_pe(Adapter(x86_call(base=base), image_base=base))
        self.assertEqual(graph.bitness, 32)
        self.assertIn(0x2000, graph.functions[0x1000].calls)
        self.assertIn(0x1000, graph.functions[0x2000].called_by)

    def test_raw_fallback_uses_x86_absolute_iat(self):
        with patch('ppm_engine.topology.callgraph._HAS_CAPSTONE', False):
            graph = CallGraph.from_pe(Adapter(x86_call()))
        self.assertIn(0x2000, graph.functions[0x1000].calls)

    def test_x86_push_arguments_are_in_call_order(self):
        code = x86_call(b'\x6a\x11\x6a\x22')
        graph = CallGraph.from_pe(Adapter(code))
        args = next(iter(track_arguments(graph, 0x2000, code, 0x1000).values()))
        self.assertEqual([int(x['value'], 0) for x in args], [0x22, 0x11])
        self.assertEqual(args[0]['reg'], '[esp+0x0]')

    def test_x86_register_value_pushed_on_stack(self):
        code = x86_call(b'\xb8\x34\x12\x00\x00\x50')
        graph = CallGraph.from_pe(Adapter(code))
        args = next(iter(track_arguments(graph, 0x2000, code, 0x1000).values()))
        self.assertEqual(int(args[0]['value'], 0), 0x1234)

    def test_x86_preallocated_stack_arguments(self):
        code = x86_call(bytes.fromhex('83 ec 08 c7 04 24 22 00 00 00 c7 44 24 04 11 00 00 00'))
        graph = CallGraph.from_pe(Adapter(code))
        args = next(iter(track_arguments(graph, 0x2000, code, 0x1000).values()))
        self.assertEqual([int(x['value'], 0) for x in args], [0x22, 0x11])

    def test_x64_rip_relative_iat_and_register_arguments(self):
        prefix = bytes.fromhex('b9 22 00 00 00 ba 11 00 00 00')
        disp = 0x2000 - (0x1000 + len(prefix) + 6)
        code = prefix + b'\xff\x15' + struct.pack('<i', disp) + b'\xc3'
        graph = CallGraph.from_pe(Adapter(code, 64, 0x140000000))
        self.assertIn(0x2000, graph.functions[0x1000].calls)
        args = next(iter(track_arguments(graph, 0x2000, code, 0x1000).values()))
        self.assertEqual([int(x['value'], 0) for x in args], [0x22, 0x11])

    def test_x64_negative_rip_displacement(self):
        code = b'\x6a\x00\xff\x15' + struct.pack('<i', 0x1000 - 0x1008) + b'\xc3'
        from ppm_engine.topology.dataflow import _parse_call_target
        from ppm_engine.topology.callgraph import Function
        graph = CallGraph()
        graph.functions[0x1000] = Function(0x1000, is_import=True)
        insn = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(code, 0x1000))[1]
        self.assertEqual(_parse_call_target(insn, 0x1000, graph), 0x1000)

    def test_pseudo_resolves_x86_import_and_string_argument(self):
        code = x86_call(b'\x55\x8b\xec\x68\x70\x12\x40\x00\x56')
        insns = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, 0x1000))
        result = PseudoCodeGenerator(32, 0x400000).generate(
            0x1000, insns, {0x2000: 'GetProcAddress'}, {0x401270: 'VStudioMain'})
        self.assertIn('GetProcAddress(esi, "VStudioMain")', result)
        self.assertIn('void sub_1000()', result)

    def test_x86_xor_loop_uses_32_bit_dec_instruction(self):
        code = bytes.fromhex('80 30 41 83 c0 01 49 75 f7 c3')
        result = XorPayloadPattern()._find_xor_functions(Adapter(code), None)
        self.assertEqual(result[0x1000]['xor_key'], '0x41')

    def test_x64_xor_loop_still_detected(self):
        code = bytes.fromhex('80 30 41 48 ff c0 ff c9 75 f6 c3')
        result = XorPayloadPattern()._find_xor_functions(Adapter(code, 64), None)
        self.assertIn(0x1000, result)

    def test_xor_outside_loop_not_reported(self):
        code = bytes.fromhex('31 d8 90 49 75 fc c3')
        self.assertEqual(XorPayloadPattern()._find_xor_functions(Adapter(code), None), {})

    def test_zeroing_xor_not_reported(self):
        code = bytes.fromhex('31 c0 49 75 fb c3')
        self.assertEqual(XorPayloadPattern()._find_xor_functions(Adapter(code), None), {})


if __name__ == '__main__':
    unittest.main()
