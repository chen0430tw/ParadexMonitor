# Session Handoff — 2026-04-10 v2

## 本次会话完成的工作

### 1. depgraph 查询准确性校准

**文件**: `engine/ppm_engine/depgraph/query.py`

- **`who_registers` 类型别名**: 添加 `_TYPE_ALIASES` 映射表，使短名可用：
  - `"ObCallback"` → `ObRegisterCallbacks`
  - `"CmCallback"` → `CmRegisterCallbackEx`, `CmRegisterCallback`
  - `"notify"` → 所有 PsSet*NotifyRoutine
  - `"minifilter"` → `FltRegisterFilter`
- 搜索范围扩展到 callback node 的 `metadata['api']` 字段
- 验证: ksafecenter64.sys 上 6/6 查询全部 PASS

### 2. Chain verdict 分类修复

**文件**: `engine/ppm_engine/propagation/chain.py`

- **`_classify_verdict` bug**: 原代码用 `step.node_id`（如 `import_ZwTerminateProcess`）与 API 名（`ZwTerminateProcess`）做集合交集，永远匹配不到。改为从 `_get_nodes()` 提取 label 后再比较
- **移除过度常见的 sink API**: `ZwSetInformationThread`、`ZwSetInformationProcess`、`MmGetSystemRoutineAddress` 从 `DANGEROUS_SINK_APIS` 移除（几乎所有驱动都导入）
- **过滤短链**: `all_interesting_chains()` 过滤 `< 3 steps` 的链（仅说明"导入了某 API"，无分析价值）
- 效果: "Interesting API chain" 垃圾 verdict 从 451 → 0

### 3. ChainTracer 缓存

**文件**: `engine/ppm_engine/propagation/chain.py`

- `_get_nodes()` 和 `_get_edges()` 添加 `_cached_nodes`/`_cached_edges`，首次调用后缓存结果
- 避免每次 `trace_from_entry`/`trace_to_sink`/`trace_callback_chain` 重复转换 dataclass → dict

### 4. Pattern 结果注入 depgraph

**文件**: `engine/ppm_engine/__main__.py`

- `_handle_analyze` Stage 6 后，将 PatternEngine 的匹配结果写入 depgraph node 的 `metadata['patterns']`
- 匹配逻辑: pattern location 落在函数 `[address, address+size)` 范围内即关联
- 下游的 chains 和 architecture 阶段可读取 pattern 信息

### 5. 假阳性大规模修复（470 驱动压测）

#### 5a. apc_inject 假阳性 (237/470 → 4/470)

**文件**: `engine/ppm_engine/patterns/apc_inject.py`

- **根因**: `MmGetSystemRoutineAddress` 单独即可触发（几乎所有驱动导入它）
- **修复**: 
  - `MmGetSystemRoutineAddress` 单独不触发
  - 需要 APC API（`KeInitializeApc`/`KeInsertQueueApc`）+ 内存操作 API（`ZwAllocateVirtualMemory`/`ZwWriteVirtualMemory`）的组合
  - APC + 仅 process access（`ObOpenObjectByPointer`）= 正常异步 I/O，不报告

#### 5b. dkom 假阳性 (全军覆没 → 3/470)

**文件**: `engine/ppm_engine/patterns/dkom.py`

- **根因 1**: `MmGetSystemRoutineAddress` 给 0.2 置信度 → 改为 0.1
- **根因 2**: offset_hits（0x2E8/0x448 等小值）在大文件中随处可见 → offset_hits 单独不加分，仅在有字符串或 API 证据时才加分
- **根因 3**: `PsInitialSystemProcess` 和 `NtBuildNumber` 是正常驱动常用字符串 → 从 `_DKOM_STRING_INDICATORS` 移除
- **门槛**: 从 0.2 提升至 0.3
- **`set()[:5]` bug**: `set` 不支持切片，导致异常被 `scan_all` 吃掉生成 conf=0.0 假 match → 改为 `list(set(...))[5:]`

#### 5c. rootkit_like 分类 (204/470 → 0/470)

**文件**: `engine/ppm_engine/reconstruct/architecture.py`

- **根因**: `classify_driver` 仅凭 `MmGetSystemRoutineAddress` 即判 `rootkit_like`
- **修复**: 移除 `rootkit_like` 自动分类（纯 import 分析不可靠）

#### 5d. scan_all 错误处理

**文件**: `engine/ppm_engine/patterns/base.py`

- `PatternEngine.scan_all()` 不再将异常包装成假 `PatternMatch(conf=0.0, loc=0)`
- 错误记录到 `self.errors` 列表供调试

### 6. 架构描述修复

**文件**: `engine/ppm_engine/reconstruct/architecture.py`

| 问题 | 修复 |
|------|------|
| "User-mode kernel-mode driver" | DLL → "dynamic library", EXE → "executable", 驱动保持 "driver" |
| "No DriverUnload" 出现在 EXE 上 | 仅对 `PE*_DRIVER` 格式检查 |
| "Writes to EPROCESS offset" 出现在 user-mode | EPROCESS offset 扫描仅对驱动执行 |

### 7. 编码问题修复

- 6 个文件中的 em dash `—` 替换为 ASCII `--`（Windows 控制台 GBK 编码不支持 UTF-8 em dash）
- 涉及文件: `chain.py`, `architecture.py`, `dkom.py`, `handle_strip.py`

### 8. 格式检测扩展

**文件**: `engine/ppm_engine/detect.py`

新增 18 种格式识别:

| 类别 | 格式 |
|------|------|
| 可分析二进制 | PE32/PE64/PE64_DLL/PE64_DRIVER, ELF32/ELF64, MACHO/MACHO_FAT, LNK |
| 图片 | JPEG, PNG, GIF, BMP, TIFF |
| 音视频 | RIFF(WAV/AVI), MKV, FLAC, OGG, MP3, MP4 |
| 文档 | PDF, ZIP(DOCX/XLSX/APK/JAR) |
| 文本 | TEXT (>85% printable 字节自动识别) |
| 其他 | SHELLCODE, TOO_SMALL, NOT_FOUND, PE_CORRUPT |

- Mach-O 64-bit 区分 x64 vs arm64（检查 CPU type 字段）

### 9. 新 Adapter: LNK (Windows 快捷方式)

**文件**: `engine/ppm_engine/adapters/lnk.py`

- 解析 MS-SHLLINK 格式: ShellLinkHeader → LinkTargetIDList → LinkInfo → StringData
- 提取: target path, arguments, working directory, icon location, show command
- **`analyze_risk()` 风险评估**:
  - 检测 LOLBin 目标 (powershell, cmd, mshta, certutil, regsvr32 等 14 个)
  - 检测可疑参数模式 (-enc, downloadstring, bypass, hidden 等 16 个)
  - 检测 Base64 编码命令
  - 检测隐藏窗口 (SW_HIDE/SW_SHOWMINNOACTIVE)
  - 检测超长参数 (>500 字符 = 混淆)
  - 输出: risk score (0-1), classification (benign/unusual/suspicious/highly_suspicious)
- `__main__.py` 集成: LNK 文件走专用分析路径，跳过二进制分析阶段

### 10. 新 Adapter: ELF 补全

**文件**: `engine/ppm_engine/adapters/elf.py`

从 stub 补全为完整实现:

| 方法 | 实现 |
|------|------|
| `imports()` | DT_NEEDED + symbol version 库解析 |
| `exports()` | 已有 |
| `sections()` | 已有 |
| `strings(min_len)` | 新增 — ASCII regex 扫描 |
| `iat_calls()` | 新增 — .text 中 E8 call → .plt/.plt.sec 映射 + pltgot_relocations 符号解析 |
| `is_driver()` | 新增 — `is_kernel_module()` 别名 |
| `_raw` | 新增 — 原始字节供 pattern 使用 |
| `_find_section()` | 新增 — 按名称查找节 |

- lief API 兼容性修复: `has_dynamic_entries` → `try/except`, `auxiliary_symbols` → `get_auxiliary_symbols`, `static_symbols` → `symbols`
- 测试: Linux `/usr/bin/ls` (ELF64) — 112 imports, 709 PLT calls, 815 strings

### 11. 新 Adapter: Mach-O 补全

**文件**: `engine/ppm_engine/adapters/macho.py`

从空 stub 重写为完整实现:

| 方法 | 实现 |
|------|------|
| `imports()` | dyld binding info → library:symbol 映射, 回退到 chained fixups 和 imported_symbols |
| `exports()` | exported_symbols |
| `sections()` | segment,section 格式 |
| `strings(min_len)` | __cstring 节优先, 回退到全文 ASCII 扫描 |
| `iat_calls()` | __text 中 BL(ARM64)/E8(x64) → __stubs 映射, 通过 LC_DYSYMTAB indirect symbol table 手动解析符号名 |
| `is_driver()` | 检查 com.apple.kpi.* 库 + KEXT_BUNDLE file type |
| `entry_point()` | LC_MAIN |
| Fat binary | 自动取第一个 slice |

- 测试: fd v10.4.2 ARM64 Mach-O — 131 imports, 11,776 stub calls (free/malloc/memcpy 等正确解析), 249 strings

### 12. 输入安全防护

**文件**: `engine/ppm_engine/__main__.py`

`_sanitize_path()` 在所有 handler 入口过滤:

| 攻击类型 | 防御 |
|----------|------|
| 协议注入 (http/ldap/jndi/file) | 检测 URL scheme 关键字, 拒绝 |
| UNC 路径 (`\\server\share`) | 检测 `\\` / `//` 前缀, 拒绝 |
| Windows 保留设备名 (CON/NUL/PRN/AUX/COM/LPT) | 正则匹配基名, 拒绝 (防 `open()` 挂起) |
| Unicode 方向覆盖 (U+202E 等) | 剥离 bidi 控制字符 |
| Null byte 截断 | 剥离 `\x00` |
| 非二进制文件 (txt/jpg/wav) | `detect.py` 正确分类, adapter 阶段 skip |

- 测试: 17 种注入攻击 + 20 种混沌输入 = **37/37 全部安全处理, 零崩溃**

### 13. 合成测试驱动 rk64.sys

**文件**: `tests/samples/rk64.sys` (5,120 bytes)

手工构造的 PE64 NATIVE driver, 嵌入全部检测触发器:

| 触发项 | 嵌入证据 |
|--------|---------|
| ob_callback (0.9) | 导入 ObRegisterCallbacks + FF 15 call site + LEA RCX handler |
| cm_callback (0.85) | 导入 CmRegisterCallbackEx + FF 15 call site |
| apc_inject (0.8) | KeInitializeApc + KeInsertQueueApc + ZwAllocateVirtualMemory + PsSetCreateProcessNotifyRoutine (4/4 stages) |
| dkom (0.5) | 字符串 PsLoadedModuleList + ActiveProcessLinks + MmUnloadedDrivers + PiDDBCacheTable |
| handle_strip | AND [reg+offset], 0xFFFFFFFE / 0x001F0021 |
| 自保护 | 无 DriverUnload, CmCallback, MmGetSystemRoutineAddress |
| 可疑字符串 | taskmgr.exe, procexp64.exe, processhacker.exe, x64dbg.exe |

分析结果: 4 patterns, 36 chains, `apc_injector` 分类, 5 callbacks, 4 self-protection

---

## 压测结果

### System32\drivers 全量扫描 (470 .sys)

| 指标 | 修复前 | 修复后 |
|------|--------|--------|
| rootkit_like 分类 | 204 (43%) | **0** |
| apc_inject pattern | 237 (50%) | **4** |
| dkom pattern | ~400 | **3** |
| generic_driver | ~50 | **420 (89%)** |
| 错误数 | 不详 | **0** |
| 最大文件 | — | RTKVHD64.sys (6.3MB) |
| 最多函数 | — | Netwtw10.sys (9,141) |

### 混沌测试 (20 种异常输入)

空文件、1字节、假MZ、随机字节、全零、全FF、ELF垃圾、LNK垃圾、JPEG伪装.sys、Python叫.exe、HTML叫.dll、1MB文本、截断PE、Mach-O垃圾、ZIP叫.exe、UTF-8 BOM — **全部安全处理, 零崩溃**

### 注入攻击测试 (17 种)

HTTP/LDAP/JNDI协议、UNC路径、设备名挂起、RTL覆盖、Null截断、SQL注入、XSS、命令注入 — **全部拦截, 零崩溃**

---

## 修改文件清单

```
engine/ppm_engine/
  __init__.py                    (未改)
  __main__.py                    ★ 路径清理 + LNK/Mach-O adapter 接入 + pattern 注入 depgraph + ELF adapter 补全
  detect.py                     ★ LNK/Mach-O 检测 + 18 种媒体/文档格式 + TEXT 启发式 + arm64 判定
  adapters/
    pe.py                        (未改)
    elf.py                       ★ 从 stub 补全: strings + iat_calls + is_driver + _raw + lief API 兼容
    macho.py                     ★ 完全重写: imports + stubs + strings + indirect symbol table
    lnk.py                       ★ 新文件: LNK 解析 + 风险评估
  depgraph/
    query.py                     ★ _TYPE_ALIASES + who_registers 搜索 metadata['api']
    build.py                     (未改)
    nodes.py                     (未改)
    edges.py                     (未改)
  propagation/
    chain.py                     ★ verdict 用 label + 缓存 + 移除常见 sink + 过滤短链
  patterns/
    base.py                      ★ scan_all 不包装错误为假 match
    apc_inject.py                ★ 需要 APC + 内存 API 组合
    dkom.py                      ★ 移除常见字符串 + offset 单独不计分 + 门槛 0.3 + set 切片 bug
    ob_callback.py               (未改)
    cm_callback.py               (未改)
    handle_strip.py              ★ em dash 替换
  reconstruct/
    architecture.py              ★ DLL/EXE 区分 + 驱动独占检查 + em dash + 移除 rootkit_like
    pseudo.py                    (未改)
tests/
  samples/
    rk64.sys                     ★ 新文件: 合成流氓驱动测试样本
docs/
  SESSION_HANDOFF_20260410_v2.md ★ 本文件
```

---

## 下一步建议

### 优先级 1: 伪代码生成测试
- `PseudoCodeGenerator` 未在真实函数上测试
- 用 ksafecenter64 的 PreOp(0x78B8) 和 CmCb(0x7C20) 做 ground truth 对比

### 优先级 2: depgraph 缓存
- `_handle_depgraph` 每次请求重建 adapter/callgraph/graph
- 加 LRU 缓存避免重复解析同一文件

### 优先级 3: ELF/Mach-O 集成到 CallGraph
- `CallGraph.from_pe()` 只支持 PE, 需要 `from_elf()` 和 `from_macho()` 让完整管线跑通

### 优先级 4: Dear ImGui GUI
- Phase 5 任务, CLI 已稳定

### 优先级 5: ObMaster 命令迁移
- C++ 插件目前全是 stub

---

## 开新会话的 prompt

> 继续优化 ParadexMonitor (D:\ParadexMonitor)。上次会话完成了: depgraph 查询校准、假阳性修复(470驱动压测 rootkit_like 204→0, apc_inject 237→4, dkom→3)、LNK/ELF/Mach-O adapter 全部实装、输入安全防护(37种攻击零崩溃)、rk64.sys 合成测试驱动。重点: 伪代码生成测试、ELF/Mach-O CallGraph 集成、depgraph 缓存。看 docs/SESSION_HANDOFF_20260410_v2.md。
