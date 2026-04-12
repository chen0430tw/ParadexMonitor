# Windows 安装包格式研究

> ppm-engine 安装包分析能力规划文档
> 2026-04-12

---

## 背景

在 ObMaster 第六次实战中，需要逆向分析云更新（YunGengXin）的卸载程序 `uninst64.exe`
来找到驱动的正确卸载方式。最终通过 NSIS 反编译发现厂商使用 `devcon64.exe remove kscsidiskadapter`
（PnP 设备移除）来卸载 KScsiDisk64.sys 驱动——而不是 IOCTL 或 NtUnloadDriver。

这个经验证明了安装包反编译在安全分析中的价值：**恶意软件的安装/卸载行为藏在安装包脚本里，
静态分析 PE 二进制找不到。**

---

## 格式概览

### 当前支持（12 种格式，全部实测验证）

| 格式 | ppm 状态 | 实现方式 | 测试文件 |
|------|---------|---------|---------|
| **PE** (exe/dll/sys) | ✅ v0.1.0+ | pefile + 自研拓扑 | ksafecenter64.sys 等 470+ |
| **ELF** (Linux) | ✅ v0.1.0+ | lief | — |
| **Mach-O** (macOS) | ✅ v0.2.0+ | lief | — |
| **LNK** (快捷方式) | ✅ v0.2.0+ | 自研解析 | — |
| **NSIS** (Nullsoft) | ✅ v0.2.3 | 自研 (nrs + Observer 参考) | uninst64.exe (729 strings, 964 entries, 21 patterns) |
| **MSI** (Windows Installer) | ✅ v0.2.3 | pymsi + olefile fallback | node-v24.msi (custom_action pattern) |
| **Inno Setup** | ✅ v0.2.3 | 自研 (签名检测 + LZMA 解压 + 字符串提取) | wiztree_setup.exe, K-Lite Codec Pack |
| **Setup Factory** | ✅ v0.2.3 | sfextract 库 | 待实际样本 |
| **7z SFX** | ✅ v0.2.3 | py7zr + 7z magic 检测 | 自制 SFX (7z.sfx + archive) |
| **ISO** (ISO 9660/UDF) | ✅ v0.2.3 | pycdlib | ubuntu-24.04.iso, KAVNETV8Plus.iso |
| **PyInstaller** | ✅ v0.2.3 | 自研 MEI/TOC 解析 | 自制 hello_test.exe (PyInstaller --onefile) |
| **MSIX/AppX** | ✅ v0.2.3 | zipfile + XML manifest | Python.3.12.Msix, UI.Xaml.AppX |

### 待支持

| 格式 | 优先级 | Python 库 | 状态 |
|------|--------|----------|------|
| **InstallShield** | P4 | 需移植 [unshield](https://github.com/twogood/unshield) (C) | 唯一未实现——需要 C binding，老样本为主 |

所有其他格式均已实现并验证。InstallShield 因为需要移植 C 库（无纯 Python 实现），暂时保留。

---

## 各格式技术细节

### NSIS (Nullsoft Scriptable Install System)

**已实现。**

- **创建者**: Nullsoft（Winamp 开发者）
- **开源**: 是 (nsis.sourceforge.io)
- **格式**: PE stub + `NullsoftInst` + `0xDEADBEEF` magic + LZMA/Zlib/Bzip2 压缩的 header + 数据区
- **脚本**: 编译后的字节码（28 字节/entry: opcode + 6 params），87 个 opcode
- **字符串**: NSIS3 Unicode = UTF-16LE null-terminated，NSIS2 = ASCII
- **变量码**: NSIS3 用 0x01-0x04，NSIS2 用 0xFD-0xFF
- **参考工具**: nrs (Python), Observer (C++), innounp (Delphi)
- **ppm 实现**: `adapters/nsis.py` — 解压 + 字符串提取（含变量展开）+ 脚本字节码 + pattern/chain 拓扑

### Inno Setup

- **创建者**: Jordan Russell
- **开源**: 是 (jrsoftware.org)
- **格式**: PE stub + 自定义 header + LZMA 压缩数据
- **脚本**: RemObjects Pascal Script（编译后的 bytecode）
- **特征**: header 中的 magic 因版本而异（1.2.10 ~ 6.7.1 跨度巨大）
- **参考工具**:
  - [innoextract](https://github.com/dscharrer/innoextract) — C++，支持 1.2.10 ~ 6.3.3，最完善
  - [innounp](https://innounp.sourceforge.net/) — Delphi，支持 2.0.7 ~ 6.1.2，可恢复 .iss 脚本
  - [InnoExtractor](https://www.havysoft.cl/innoextractor.html) — GUI，可反编译 Pascal Script
- **实现策略**: 移植 innoextract 的 header 解析逻辑到 Python，提取字符串和 Pascal Script

### MSI (Windows Installer)

- **创建者**: 微软
- **格式**: OLE2 Compound Binary File (和 .doc/.xls 同源)
- **数据库**: 内部是关系数据库（tables: File, Registry, CustomAction, Property 等）
- **安全重点**: `CustomAction` 表可包含任意可执行代码（DLL/EXE/VBScript/JScript）
- **参考工具**:
  - [pymsi](https://github.com/nightlark/pymsi) — 纯 Python，`pip install python-msi`
  - [msidump](https://github.com/mgeeky/msidump) — Python 安全分析专用，YARA 集成
  - [msi-utils](https://pypi.org/project/msi-utils/) — Python 分析工具
  - [lessmsi](https://github.com/activescott/lessmsi) — C# GUI
- **实现策略**: 用 pymsi 解析 OLE2 结构，提取 CustomAction + Registry + File 表，跑 pattern 检测

### Setup Factory

- **创建者**: Indigo Rose Software
- **格式**: PE stub + 专有压缩格式（zlib-based）
- **版本**: V5 ~ V10，每个版本格式略有不同
- **特征**: 无公开格式规范
- **参考工具**:
  - [sfextract](https://github.com/CybercentreCanada/sfextract) — Python，加拿大网络安全中心出品，基于 SFUnpacker
  - [SFUnpacker](https://github.com/Puyodead1/SFUnpacker) — C++，仅支持 V9，源自 Observer
  - [Observer sfact 模块](https://github.com/lazyhamster/Observer) — C++，多版本支持
- **关系链**: Observer sfact → SFUnpacker (C++) → sfextract (Python 移植)
- **实现策略**: 依赖 sfextract 库或移植其核心解析逻辑

### InstallShield

- **创建者**: Revenera (原 Flexera)
- **格式**: 多种变体（CAB-based, MSI-based, Script-based）
- **版本**: V5 ~ V2025，格式变化大
- **参考工具**:
  - [unshield](https://github.com/twogood/unshield) — C 库 + CLI
  - [Observer ishield 模块](https://github.com/lazyhamster/Observer) — C++
- **实现策略**: 通过 ctypes 调 unshield 或移植核心 CAB 解析

### 7z SFX (自解压 7-Zip)

- **格式**: PE stub (7zSD.sfx) + 7z 压缩包
- **特征**: 7z magic `7z\xBC\xAF\x27\x1C` 在 PE stub 之后
- **参考工具**:
  - [py7zr](https://pypi.org/project/py7zr/) — 纯 Python 7z 解压
  - 7z CLI
- **安全重点**: 勒索软件常用 7z SFX 投递
- **实现策略**: 定位 7z magic → py7zr 解压 → 分析内容

### ISO

- **格式**: ISO 9660 / UDF
- **参考工具**:
  - [pycdlib](https://pypi.org/project/pycdlib/) — 纯 Python ISO 解析
  - [Observer isoimg 模块](https://github.com/lazyhamster/Observer)
- **安全重点**: 2022 年起大量钓鱼邮件使用 ISO 附件绕过 MOTW (Mark of the Web)
- **实现策略**: pycdlib 解析目录结构，提取 PE/LNK/脚本文件信息

### PyInstaller

- **格式**: PE stub + 自定义 TOC (Table of Contents) + zlib 压缩的 Python 模块
- **特征**: `MEI` 或 `PYZ` magic
- **参考工具**:
  - [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) — Python 提取器
- **安全重点**: Python 恶意软件（stealer、RAT）首选打包方式
- **实现策略**: 移植 pyinstxtractor 的 TOC 解析，提取 .pyc 文件列表和入口点

### MSIX / AppX

- **格式**: ZIP + AppxManifest.xml + 签名
- **参考工具**: Python `zipfile` 原生
- **实现策略**: zipfile 解压 → 解析 AppxManifest.xml 提取权限和入口点
- **备注**: 恶意样本极少，加入主要是格式覆盖完整度

---

## Observer 项目参考

[Observer](https://github.com/lazyhamster/Observer) 是 FAR Manager 的万能解包插件，
C++ 实现，支持 22 种格式。其模块结构是 ppm 安装包支持的路线图：

| Observer 模块 | 对应格式 | ppm 状态 | 参考价值 |
|--------------|---------|---------|---------|
| nsis | NSIS | ✅ 已参考 | opcode 表 + 变量码 + 版本检测 |
| msi | MSI | ✅ 已实现 | pymsi API 参考 |
| ishield | InstallShield | 待做 | CAB 格式处理 |
| sfact | Setup Factory | ✅ 已实现 | 通过 sfextract（SFUnpacker Python 移植） |
| wise | Wise Installer | 低优先级 | 已停产 |
| vise | MindVision VISE | 低优先级 | Mac/Win 安装包 |
| inst4j | install4j | 低优先级 | Java 安装包 |
| isoimg | ISO 镜像 | ✅ 已实现 | pycdlib |
| pst/mbox/mime | 邮件格式 | 未来方向 | 钓鱼分析 |
| pdf | PDF 文档 | 未来方向 | 恶意文档分析 |

---

## 测试方法论

### Mythos 思维：缺样本就自己造

不需要到处找测试样本——自己就能生成：

| 格式 | 生成方法 | 耗时 |
|------|---------|------|
| **PyInstaller** | `echo 'print("hello")' > t.py && pyinstaller --onefile t.py` | 10 秒 |
| **7z SFX** | `7z a t.7z file.txt && cat 7z.sfx t.7z > t.exe` | 5 秒 |
| **NSIS** | 用 makensis 编译 .nsi 脚本 | 1 分钟 |
| **Inno Setup** | 用 iscc 编译 .iss 脚本 | 1 分钟 |
| **ISO** | `mkisofs -o t.iso folder/` 或 PowerShell `New-ISOFile` | 10 秒 |
| **MSI** | WiX Toolset 或 `msilib` Python 标准库 | 1 分钟 |
| **MSIX** | `makeappx pack /d folder /p t.msix` | 10 秒 |

**核心：先找现成的替死鬼，找不到就自己变成那个替死鬼。**

### 实际测试记录（2026-04-12）

| 格式 | 测试文件 | 来源 | detect | analyze |
|------|---------|------|--------|---------|
| NSIS | uninst64.exe | 云更新备份 | ✅ NSIS_UNINST | ✅ 21 patterns, 6 chains |
| NSIS | BaiduNetdisk_7.37.exe | Downloads | ✅ NSIS_UNINST | ✅ |
| Inno Setup | wiztree_setup.exe | Downloads | ✅ INNO_SETUP | ✅ |
| Inno Setup | K-Lite_Codec_Pack.exe | Downloads | ✅ INNO_SETUP | ✅ |
| MSI | node-v24.13.1-x64.msi | G:\ | ✅ MSI | ✅ custom_action |
| ISO | ubuntu-24.04.iso | E:\ | ✅ ISO | ✅ |
| ISO | KAVNETV8Plus.iso | D:\BaiduNetdisk | ✅ ISO | ✅ |
| AppX | UI.Xaml.appx | G:\ | ✅ MSIX | ✅ |
| MSIX | Python.3.12.Msix | G:\ | ✅ MSIX | ✅ |
| PyInstaller | hello_test.exe | **自制** | ✅ PYINSTALLER | ✅ |
| 7z SFX | test_sfx.exe | **自制** | ✅ SFX_7Z | ✅ |

---

## 实现原则

1. **安全分析优先，不是解包工具** — ppm 提取安全相关信息（脚本命令、注册表操作、服务控制、文件投递），不是通用解压缩器
2. **拓扑分析复用** — 所有安装包格式接入同一套 pattern/chain 分析管线
3. **有 Python 库就用，没有就移植核心逻辑** — 不依赖外部 CLI 工具
4. **格式检测在 detect.py，分析在 adapters/，拓扑在 __main__.py** — 保持架构一致
5. **缺样本就自己造** — PyInstaller/7z SFX/ISO 等格式，10 秒生成测试文件
