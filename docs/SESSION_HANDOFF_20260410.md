# Session Handoff — 2026-04-10

## 本次会话完成的工作

### 1. ObMaster `/notify registry` 命令（完整）

**代码**：`D:\ObMaster\src\cmd_notify.cpp`

实现了 `CmpCallBackVector` 扫描：
- 扫描 `CmUnRegisterCallback` + `CmRegisterCallback` 导出函数中的 RIP-relative LEA
- 只保留 `.data` 节候选，用 `LooksLikeCmArray()` 验证
- 三层假阳性过滤：fn 回指数组、kernel VA first QWORD、零字节密度
- 三条 kill 路径：`--kill <drv>`（名称）、`--kill-kva <dobj>`（DriverObject 范围）、`--kill-unknown`

**Bug 修复**：
- `LooksLikeCmArray` owner 空串检查
- 主循环 fn-in-array 过滤
- Code prologue 启发式改为 block-in-module 检查，最终改为 first QWORD kernel VA 检查

### 2. ksafecenter64.sys 完整逆向

**结论写在** `D:\ObMaster\docs\VBOX_DEBUG.md` 第四次实战章节。

关键发现：
- **CmCallback** (`0x140007C20`)：只拦截 `RegNtPreSetValueKey`，保护 `\SOFTWARE\kSafeCenter`，**不产生任何句柄**
- **ObOpenObjectByPointer** 两个调用点：都只用 `DesiredAccess=0x200`（QUERY_INFO），**不产生 0x1FFFFF 句柄**
- **之前文档说"CmCallback → evil handle"是错误推断**
- Evil handle 的真正来源仍待确认（可能是 kboot64.sys 或内核自身行为）

### 3. ObMaster 帮助页面重构

`src/main.cpp` Usage() 改为 lambda `H()` 格式，8 个逻辑分组，加新命令只需一行。

### 4. Paradex Process Monitor 项目建立

**仓库**：https://github.com/chen0430tw/ParadexMonitor

#### C++ 侧（ppm.exe）
- 插件系统：`IPlugin` + `Command` + `PluginRegistry` + `PPM_PLUGIN()` 宏
- 9 个插件，62 个命令槽位
- 跨平台：CMake + Ninja，GCC (Cygwin) 编译通过，MSVC 就绪
- CLI 模式 + `--json` Agent 模式 + `--quiet` 静默模式

#### Python 侧（ppm-engine）
8 个包，30+ 模块：

| 包 | 模块 | 状态 |
|---|------|------|
| adapters | PE (pefile, IAT scan, strings), ELF (lief), Mach-O (stub) | 实装 |
| unpack | entropy, xor_crack, encoding, detect (壳识别), topo_strip | 实装 |
| topology | callgraph (capstone x64), coupling (Jaccard), dataflow (stub) | 实装 |
| depgraph | nodes, edges, build (12 API), query (6 查询), render (DOT+ASCII), diff | 实装 |
| propagation | ChainTracer (DFS/BFS, 19 条链) | 实装 |
| reconstruct | PseudoCodeGenerator (18 API 签名), ArchitectureReconstructor (11 分类) | 实装 |
| patterns | ObCallback, CmCallback, APC inject, DKOM, handle strip (5 模式) | 实装 |
| bridges | QCU, URP, exMs, HCE (4 桥接) | 实装 |

#### 验证结果（ksafecenter64.sys，8/8 全过）
```
detect     → PE64_DRIVER, x64, not packed
adapter    → 289 IAT calls, 336 strings
callgraph  → 252 functions, 21 roots
depgraph   → 539 nodes, 528 edges
patterns   → ObCallback(0.8) + CmCallback(0.8) + DKOM(0.4)
chains     → 19 interesting chains
architecture → protection_minifilter
```

---

## 下一步：优化方向

### 优先级 1：analyze pipeline 完善
- `__main__.py` 的 `_handle_analyze` 已接通，但各阶段间数据传递可以更紧密
- callgraph → depgraph → chains 应该共享同一个 adapter 实例（避免重复解析 PE）
- patterns 的结果应该注入到 depgraph 的 nodes/edges 中（标注哪些函数匹配了什么模式）

### 优先级 2：depgraph 查询准确性
- `who_registers("ObCallback")` 返回空——query key 需要匹配 import 名 `ObRegisterCallbacks` 而非类型名
- `find_sinks` 返回 6 条链但未验证准确性
- 需要用 ksafecenter64 的已知逆向结果做 ground truth 校准

### 优先级 3：伪代码质量
- `PseudoCodeGenerator` 有框架但未用真实函数测试
- 应该对 ksafecenter64 的 `PreOp(0x78B8)` 和 `CmCb(0x7C20)` 生成伪代码并与手动逆向结果对比

### 优先级 4：Agent 摸鱼修复
- Agent #5 写的 `__main__.py` 用了不存在的函数名（`build_callgraph` 等），已手动修复
- 后续 Agent 任务需要加验证步骤：必须实际调用函数而不是包在 try/except 里跳过

### 优先级 5：Dear ImGui GUI
- Phase 5 任务，当前 CLI 优先
- `tab_analysis`、`tab_topology`、`topology_view` 待实现

### 优先级 6：ObMaster 命令迁移
- 当前 ppm 的命令都是 stub（printf 占位）
- 需要把 ObMaster 的实际实现代码搬过来
- 优先迁移：proc, drivers, obcb, notify, handles（最常用的）

---

## 关键文件索引

```
D:\ObMaster\                            ← 现有内核工具
  src\cmd_notify.cpp                    ← /notify registry 实现
  docs\VBOX_DEBUG.md                    ← ksafecenter64 逆向全记录
  docs\ksafe_architecture.md            ← 云更新驱动栈分析

D:\ParadexMonitor\                      ← 新项目
  docs\whitepaper.md                    ← 技术白皮书（架构、管线、6 期计划）
  docs\SESSION_HANDOFF_20260410.md      ← 本文件
  CMakeLists.txt                        ← 构建配置
  ppm\core\                             ← C++ 核心框架
  ppm\plugins\                          ← 9 个插件（stub）
  engine\ppm_engine\                    ← Python 分析引擎（实装）
  engine\pyproject.toml                 ← Python 依赖

D:\ObMaster\docs\ksafecenter64.sys      ← 测试用驱动二进制
```

## 开新会话的 prompt

> 继续优化 ParadexMonitor (D:\ParadexMonitor)。上次会话建好了项目骨架，C++ 9 插件 + Python 8 包全部实装，ksafecenter64.sys 全管线 8/8 通过。重点：depgraph 查询准确性校准、伪代码生成测试、pipeline 数据共享优化。看 docs/SESSION_HANDOFF_20260410.md 和 docs/whitepaper.md。
