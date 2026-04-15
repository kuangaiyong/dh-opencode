# OpenCode 安全机制移植详解

> 来源：参考 Claude Code 企业级安全机制，移植到 OpenCode 项目
> 分支：`master`（主干），已推送 v1.1.0
> 日期：2026-04-03 ~ 2026-04-04

---

## 目录

1. [架构总览](#1-架构总览)
2. [模块依赖关系图](#2-模块依赖关系图)
3. [权限决策链（完整流程）](#3-权限决策链完整流程)
4. [模块一：路径安全保护](#4-模块一路径安全保护)
5. [模块二：Bash 命令安全验证](#5-模块二bash-命令安全验证)
6. [模块三：危险权限规则过滤](#6-模块三危险权限规则过滤)
7. [模块四：只读命令自动批准（Bash）](#7-模块四只读命令自动批准bash)
8. [模块五：只读命令自动批准（PowerShell）](#8-模块五只读命令自动批准powershell)
9. [模块六：AI 权限分类器](#9-模块六ai-权限分类器)
10. [集成方式详解](#10-集成方式详解)
11. [配置项汇总](#11-配置项汇总)
12. [文件清单](#12-文件清单)
13. [尚未移植的模块](#13-尚未移植的模块)

---

## 1. 架构总览

已移植的安全体系分为 **6 大防御层**，形成纵深防御：

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 6: AI 权限分类器（2 阶段自动决策）                          │
│  Layer 5: 只读命令自动批准（Bash 46+ 命令 + PS 60+ cmdlet）       │
│  Layer 4: Bash/PowerShell 命令安全验证（16 个验证器）               │
│  Layer 3: 路径安全保护（危险文件/目录 + Windows NTFS 攻击防护）     │
│  Layer 2: 危险权限规则过滤（防止过于宽泛的 allow 规则）              │
│  Layer 1: 权限评估流水线（deny → ask → allow 基础规则匹配）        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. 模块依赖关系图

```
tool/bash.ts
  ├── security/bash-security.ts (validateBashCommand)
  │     └── security/bash-patterns.ts (模式常量、正则、Zsh 危险命令集)
  ├── security/readonly-commands.ts (isReadOnlyCommand) [Bash]
  └── security/readonly-powershell.ts (isReadOnlyPowerShellCommand) [PS]

permission/index.ts（中央集成点）
  ├── security/path-safety.ts (checkPathsSafety)
  ├── permission/dangerous-rules.ts (stripDangerousRules)
  │     └── security/bash-patterns.ts (DANGEROUS_BASH/POWERSHELL_PATTERNS)
  ├── permission/classifier.ts (Classifier.classify)
  │     ├── permission/classifier-allowlist.ts (安全白名单、危险模式、高风险权限)
  │     ├── permission/denial-tracking.ts (拒绝计数追踪)
  │     └── permission/classifier-prompt.ts (Stage 1/2 提示词模板)
  └── permission/evaluate.ts (规则匹配引擎)
```

---

## 3. 权限决策链（完整流程）

`permission/index.ts` 的 `ask()` 函数是所有安全模块的中央集成点，严格按以下顺序执行：

```
[1] 危险规则过滤 — stripDangerousRules()
    → 如 classifier 启用，从 ruleset 中移除过于宽泛的 allow 规则
    → 仅过滤 config/project ruleset，不过滤 session-level approved rules

[2] 规则评估 — evaluate()
    → 全局 deny 规则 → 硬性拒绝（DeniedError）
    → 全局 allow 规则 → 直接通过
    → 否则 → needsAsk = true

[3] 路径安全检查 — checkPathsSafety()
    → safe: false + classifierApprovable:false → 跳过 acceptEdits + 跳过分类器
    → safe: false + classifierApprovable:true  → 跳过 acceptEdits（分类器仍可审批）

[4] Bash 安全元数据检查
    → 如 bashSecurityMessage 存在 → 跳过 acceptEdits + 跳过分类器

[5] acceptEdits 快速路径
    → 如未被跳过 && permission="edit" && 工具为编辑类 && 路径在项目内
    → 自动批准

[6] AI 分类器 — Classifier.classify()
    → allow → 自动批准
    → escalate/错误 → 进入用户提示

[7] 用户提示（最终回退）
    → 创建 pending request，发布 BusEvent，等待用户回复
```

---

## 4. 模块一：路径安全保护

**文件**: `security/path-safety.ts`（241 行）

### 功能概述

检测文件操作中的危险路径，防止 AI 意外修改关键系统文件或受版本控制保护的目录。

### 危险文件列表

```typescript
DANGEROUS_FILES = [
  ".gitconfig", ".gitmodules", ".bashrc", ".bash_profile",
  ".zshrc", ".zprofile", ".profile", ".ripgreprc",
  ".mcp.json", "opencode.json"
]
```

### 危险目录列表

```typescript
DANGEROUS_DIRECTORIES = [
  ".git", ".vscode", ".idea", ".claude", ".opencode"
]
```

### Windows 特殊攻击防护（7 项）

`hasSuspiciousWindowsPathPattern()` 检测以下攻击向量：

| 攻击类型 | 检测模式 | 说明 |
|---------|---------|------|
| NTFS ADS | `:` 在位置 2 之后 | `file.txt:Zone.Identifier` 可隐藏数据 |
| 8.3 短名 | `~\d` | `DOCUME~1` 可绕过路径检查 |
| 长路径前缀 | `\\?\`, `\\.\`, `//?/`, `//./` | 绕过 MAX_PATH 限制 |
| 尾部点/空格 | 文件名以 `.` 或空格结尾 | Windows 会静默剥离 |
| DOS 设备名 | `CON\|PRN\|AUX\|NUL\|COM[1-9]\|LPT[1-9]` | Windows 保留设备名 |
| 三重点号 | `...` 作为路径组件 | 可能导致路径遍历 |
| UNC 路径 | `\\server\share` 或 `//server/share` | 网络共享访问 |

### 核心逻辑流程

```
checkPathSafety(filePath)
  ├─ hasSuspiciousWindowsPathPattern(filePath)?
  │   └─ YES → { safe: false, classifierApprovable: false }  // 硬性阻止
  ├─ isDangerousFilePath(filePath)?
  │   └─ YES → { safe: false, classifierApprovable: true }   // 分类器可审批
  └─ return { safe: true }
```

### 关键设计决策

- **分类器可审批性**：可疑 Windows 模式（ADS、8.3 短名等）是硬性阻止，AI 分类器也不能批准；而危险文件/目录（如 `.gitconfig`）允许分类器审批，因为某些合法操作确实需要修改这些文件。
- **平台感知**：`getPlatformKind()` 返回 `windows | wsl | posix`，NTFS ADS 检查仅在 Windows/WSL 上启用。
- **大小写不敏感**：`normalizeCaseForComparison()` 对所有路径做 `toLowerCase()` 处理，防御 NTFS/HFS+ 大小写差异。

---

## 5. 模块二：Bash 命令安全验证

**文件**: `security/bash-patterns.ts`（135 行）+ `security/bash-security.ts`（656 行）

### 功能概述

在命令执行前进行 16 项安全检查，检测注入攻击、混淆技术、解析器差异利用等威胁。

### 安全模式常量（bash-patterns.ts）

#### 跨平台代码执行命令（21 个）

```typescript
CROSS_PLATFORM_CODE_EXEC = [
  "python", "python3", "python2", "node", "deno", "tsx",
  "ruby", "perl", "php", "lua", "npx", "bunx",
  "npm run", "yarn run", "pnpm run", "bun run",
  "bash", "sh", "ssh"
]
```

#### 危险 Bash 模式（27 个）

`CROSS_PLATFORM_CODE_EXEC` + `zsh`, `fish`, `eval`, `exec`, `env`, `xargs`, `sudo`

#### 危险 PowerShell 模式（28 个）

`CROSS_PLATFORM_CODE_EXEC` + `powershell`, `pwsh`, `cmd`, `cmd.exe`, `Invoke-Expression`, `iex`, `Start-Process`

#### 命令替换模式（13 个正则）

| 模式 | 说明 |
|------|------|
| `<()`, `>()` | 进程替换 |
| `=()` | Zsh 进程替换 |
| `$(`, `${` | 命令/变量替换 |
| `$[`, `~[` | 算术替换 / Zsh glob |
| `(e:` | Zsh glob 限定符 |
| `(\+` | Zsh glob 限定符 |
| `` }\\s\*always\\s\*{ `` | Zsh always 块 |
| `<#` | PowerShell 多行注释 |

#### 其他常量

- **`ZSH_DANGEROUS_COMMANDS`**（19 个）：`zmodload`, `emulate`, `sysopen/read/write/seek`, `zpty`, `ztcp`, `zsocket`, `mapfile`, `zf_*` 系列
- **`UNICODE_WS_RE`**：Unicode 空白字符检测正则
- **`CONTROL_CHAR_RE`**：非打印控制字符检测正则

### 16 个安全验证器（bash-security.ts）

验证器分为两类：
- **解析器差异（Misparsing）**：一旦触发立即返回，优先级最高
- **非解析器差异（Non-misparsing）**：延迟判定，如果后续有 misparsing 结果则被覆盖

| # | 验证器 | 优先级 | 类型 | 检查内容 |
|---|--------|--------|------|---------|
| 1 | `validateObfuscatedFlags` | P1 | Misparsing | ANSI-C 引号十六进制转义（`$'\x2d'`）、locale 引用（`$"`）、空引号对（`''''`） |
| 2 | `validateShellMetacharacters` | P1 | Non-misparsing | 参数中未引用的 `;`, `\|`, `&` |
| 3 | `validateDangerousVariables` | P1 | Non-misparsing | 重定向目标中的变量（`> $VAR`）或管道源中的变量 |
| 4 | `validateCommentQuoteDesync` | P1 | Misparsing | 未引用 `#` 注释中包含引号字符（可能脱同步） |
| 5 | `validateCarriageReturn` | P0 | Misparsing | 双引号外的回车符（shell-quote 和 bash 解析差异） |
| 6 | `validateNewlines` | P0 | Non-misparsing | 换行后跟非空白字符（隐藏多命令） |
| 7 | `validateIFSInjection` | P1 | Misparsing | `$IFS` 或 `${...IFS`（绕过安全验证） |
| 8 | `validateProcEnvironAccess` | P1 | Non-misparsing | `/proc/*/environ` 访问（暴露环境变量） |
| 9 | `validateDangerousPatterns` | P0 | Misparsing | 反引号 + 所有命令替换模式 |
| 10 | `validateRedirections` | P0 | Non-misparsing | 完全未引用内容中的输入（`<`）或输出（`>`）重定向 |
| 11 | `validateBackslashEscapedWhitespace` | P1 | Misparsing | 引号外的 `\ ` 或 `\tab`（路径遍历） |
| 12 | `validateBackslashEscapedOperators` | P1 | Misparsing | 引号外的 `\;`, `\|`, `\&`, `\<`, `\>` |
| 13 | `validateUnicodeWhitespace` | P0 | Misparsing | Unicode 空白字符（解析不一致性） |
| 14 | `validateMidWordHash` | P1 | Misparsing | 非空白字符后的 `#`（shell-quote vs bash 解析差异） |
| 15 | `validateBraceExpansion` | P1 | Misparsing | 引号外的 `{a,b}` 或 `{1..5}` 模式 |
| 16 | `validateZshDangerousCommands` | P1 | Misparsing | Zsh 危险命令基命令或 `fc -e`（通过编辑器执行任意命令） |

**预检查**：`validateControlCharacters`（P0）— 在构建上下文前单独运行，检测原始命令中的控制字符。

### 核心验证流程

```
validateBashCommand(command)
  ├─ 空命令? → { safe: true }
  ├─ validateControlCharacters → { safe: false, isMisparsing: true }
  ├─ 构建 ValidationContext（baseCommand、各种 unquoted 变体）
  ├─ 依次运行 16 个验证器:
  │   ├─ misparsing 验证器触发 → 立即返回
  │   └─ non-misparsing 验证器触发 → 延迟记录，继续检查
  ├─ 有延迟结果 → 返回延迟结果
  └─ 全部通过 → { safe: true }
```

### 辅助函数

| 函数 | 说明 |
|------|------|
| `extractQuotedContent(command)` | 解析单/双引号边界，返回三种变体 |
| `stripSafeRedirections(content)` | 移除 `2>&1`, `>/dev/null`, `< /dev/null` |
| `hasUnescapedChar(content, char)` | 检查未转义字符 |
| `buildContext(command)` | 构建 ValidationContext 对象 |

---

## 6. 模块三：危险权限规则过滤

**文件**: `permission/dangerous-rules.ts`（142 行）

### 功能概述

防止用户或项目配置中过于宽泛的 `allow` 规则（如 `bash: * → allow`）绕过安全检查。

### 核心函数

#### `isDangerousBashPattern(pattern)`

检查 Bash 权限规则模式是否危险：

```
匹配规则:
  → "*"                      (通配所有命令)
  → 精确匹配 DANGEROUS_BASH_PATTERNS  (如 "sudo")
  → "prefix:*"               (如 "bash:*")
  → "prefix*"                (如 "sudo*")
  → "prefix *"               (如 "eval *")
  → "prefix -*...*"          (如 "python -*args*")
```

#### `isDangerousPowerShellPattern(pattern)`

与 Bash 版本相同，额外检查 `.exe` 变体（如 `powershell.exe`）。

#### `isDangerousRule(rule)`

仅检查 `action: "allow"` 且 `permission` 为 `"bash"` 或 `"powershell"` 的规则。`deny` 和 `ask` 规则永远不会被认为是危险的。

#### `stripDangerousRules(ruleset)`

返回过滤后的 ruleset，移除所有危险规则。如果没有变化，返回原引用（避免不必要的复制）。

### 集成方式

在 `permission/index.ts` 的 `ask()` 函数中，**在规则评估循环之前**调用：

```typescript
// 仅在 classifier 启用时生效
if (classifierEnabled) {
  ruleset = stripDangerousRules(ruleset)
}
```

**安全设计**：
- 只过滤 config/project ruleset
- 不过滤 session-level approved rules（用户本次会话手动批准的）
- Fail-open：配置读取失败时不 strip（保持原始行为）

---

## 7. 模块四：只读命令自动批准（Bash）

**文件**: `security/readonly-commands.ts`（1444 行）

### 功能概述

识别安全的只读命令，自动跳过权限提示，减少用户交互次数。

### 命令分类

#### A. 简单只读命令（46 个）

无需标志验证，任何非 shell 元字符参数都安全：

```
cat, head, tail, wc, stat, strings, hexdump, od, nl, tac, rev,
basename, dirname, realpath, readlink, cut, paste, tr, column, fold,
expand, unexpand, fmt, comm, cmp, numfmt, diff, id, uname, free,
df, du, locale, groups, nproc, cal, uptime, date, hostname, sleep,
which, type, expr, test, getconf, seq, tsort, pr, true, false
```

#### B. 精确正则匹配（14 个）

| 命令 | 安全模式 |
|------|---------|
| `echo` | 安全参数 |
| `uniq` | 仅标志 |
| `pwd`, `whoami`, `arch` | 无参数或仅标志 |
| `node -v`, `node --version` | 版本查询 |
| `python --version`, `python3 --version` | 版本查询 |
| `history`, `alias` | 无参数 |
| `ls` | 通用列出 |
| `find` | 排除 `-delete/-exec/-ok/-fprint*/-fls/-fprintf` |
| `cd` | 目录切换 |
| `jq` | 排除 `-f/--from-file/--rawfile/--slurpfile/-L` 等 |

#### C. 标志验证命令（25 个配置，~250 个安全标志）

每个命令有独立的 `safeFlags` 配置，支持：
- 布尔标志（`--verbose`）
- 带值标志（`--format=VALUE`）
- 组合短标志（`-abc`）
- `--` 终止符
- `isDangerous` 自定义回调

| 命令 | 安全标志数 | 自定义安全检查 |
|------|----------|--------------|
| `git status` | 17 | 无 |
| `git diff` | 42 | 无 |
| `git log` | 40 | 无 |
| `git show` | 15 | 无 |
| `git blame` | 14 | 无 |
| `git branch` | 15 | 无 `--list/-a/-r` 且有位置参数时拒绝 |
| `git tag` | 9 | 无 `--list/-l` 且有位置参数时拒绝 |
| `git remote` | 2 | 仅允许 bare、`-v`、`show <name>`、`get-url <name>` |
| `git ls-files` | 20 | 无 |
| `git stash list` | 9 | 无 |
| `git stash show` | 9 | 无 |
| `git config` | 10 | 仅允许 `--get`、`--get-all`、`--list` |
| `git ls-remote` | 8 | 拒绝含 `://`, `@`, `:`, `$` 的 URL |
| `git rev-parse` | 22 | 无 |
| `git rev-list` | 21 | 无 |
| `git shortlog` | 9 | 无 |
| `git describe` | 13 | 无 |
| `git cat-file` | 8 | 无 |
| `git reflog` | 6 | 无 |
| `grep` | 46 | 无 |
| `rg` (ripgrep) | 58 | 无 |
| `tree` | 28 | `-o` 被排除 |
| `sort` | 26 | 无 |
| `file` | 26 | 无 |

### 安全防护机制

| 防护 | 说明 |
|------|------|
| 变量展开 | `$VAR`, `${VAR}` → 拒绝 |
| 命令替换 | `$()`, 反引号 → 拒绝 |
| Glob | `*`, `?`, `[]` → 拒绝 |
| UNC 路径 | `\\server\share` → 拒绝 |
| 复合命令拆分 | 在 `\|`, `&&`, `\|\|`, `;` 处拆分，每子命令都必须只读 |
| cd + git 组合 | 同一复合命令中同时出现 cd 和 git → 拒绝（沙箱逃逸防护） |
| git 危险标志 | `-c`, `--exec-path`, `--config-env` → 拒绝（代码执行防护） |

### 验证流程

```
isReadOnlyCommand(command)
  ├─ 空命令? → { readonly: false }
  ├─ containsUncPath? → { readonly: false }
  ├─ containsUnsafeExpansion? → { readonly: false }
  ├─ splitSubcommands → 子命令数组
  ├─ cd + git 同时存在? → { readonly: false }
  └─ 对每个子命令:
      isSingleCommandReadOnly(sub)
        ├─ 移除安全重定向（>/dev/null, 2>&1）
        ├─ 检查 UNC 路径、不安全展开
        ├─ 尝试 EXACT_MATCH_REGEXES
        ├─ 尝试 COMMAND_ALLOWLIST（标志验证 + isDangerous 回调）
        ├─ 尝试 SIMPLE_READONLY_COMMANDS
        └─ 全部失败 → { readonly: false }
```

### 关键辅助函数

| 函数 | 说明 |
|------|------|
| `containsUnsafeExpansion(command)` | 检测引号外的 `$VAR`, `${}`, `$()`, 反引号, glob |
| `containsUncPath(command)` | 检测 UNC 路径 |
| `splitSubcommands(command)` | 按管道/逻辑运算符/分号拆分，尊重引号 |
| `tokenize(command)` | 分词，处理单/双引号和转义 |
| `validateFlags(tokens, startIndex, config)` | 验证标志是否在 safeFlags 中 |

---

## 8. 模块五：只读命令自动批准（PowerShell）

**文件**: `security/readonly-powershell.ts`（891 行）

### 功能概述

PowerShell 版本的只读命令验证器，支持 60+ cmdlet 白名单、别名解析、标志验证。

### 核心常量

#### PowerShell 通用参数（12 个）

```typescript
COMMON_PARAMETERS = [
  "-verbose", "-debug", "-erroraction", "-warningaction",
  "-informationaction", "-progressaction", "-errorvariable",
  "-warningvariable", "-informationvariable", "-outvariable",
  "-outbuffer", "-pipelinevariable"
]
```

#### 别名映射（38 个）

| 别名 | Cmdlet |
|------|--------|
| `cd` | `Set-Location` |
| `ls`, `dir` | `Get-ChildItem` |
| `cat` | `Get-Content` |
| `pwd` | `Get-Location` |
| `echo` | `Write-Output` |
| `?` | `Where-Object` |
| `%` | `ForEach-Object` |
| `select` | `Select-Object` |
| `sort` | `Sort-Object` |
| `gps` | `Get-Process` |
| ... | ... |

#### Cmdlet 白名单（按类别）

| 类别 | Cmdlet | 标志处理 |
|------|--------|---------|
| 文件系统（读） | `Get-ChildItem`, `Get-Content`, `Get-Item`, `Get-ItemProperty`, `Test-Path`, `Resolve-Path`, `Get-FileHash`, `Get-Acl` | 各自独立验证 |
| 导航 | `Set-Location`, `Push-Location`, `Pop-Location` | 全部标志允许 |
| 文本搜索 | `Select-String` | 独立验证 |
| 数据转换 | `ConvertTo-Json`, `ConvertFrom-Json`, `ConvertTo-Csv`, `ConvertFrom-Csv`, `ConvertTo-Xml`, `ConvertTo-Html`, `Format-Hex` | 全部标志允许 |
| 对象检查 | `Get-Member`, `Get-Unique`, `Compare-Object`, `Join-String`, `Get-Random` | 全部标志允许 |
| 路径工具 | `Convert-Path`, `Join-Path`（排除 `-Resolve`）, `Split-Path`（排除 `-Resolve`） | 独立验证 |
| 系统信息 | `Get-Process`, `Get-Service`, `Get-ComputerInfo`, `Get-Host`, `Get-Date`, `Get-Location`, `Get-PSDrive`, `Get-Module`, `Get-Alias`, `Get-History`, `Get-Culture`, `Get-UiCulture`, `Get-TimeZone`, `Get-Uptime`, `Get-PSProvider`, `Get-HotFix` | 全部标志允许 |
| 格式化 | `Format-Table`, `Format-List`, `Format-Wide`, `Format-Custom`, `Measure-Object`, `Select-Object`, `Sort-Object`, `Group-Object`, `Where-Object`, `Out-String`, `Out-Host`, `Out-Null`, `Tee-Object` | 全部标志允许 |
| 网络 | `Get-NetAdapter`, `Get-NetIPAddress`, `Get-NetIPConfiguration`, `Get-NetRoute`, `Get-DnsClientCache`, `Get-DnsClient` | 全部标志允许 |
| 事件日志 | `Get-EventLog`, `Get-WinEvent` | 排除 `-FilterXml`, `-FilterHashtable`（XXE 风险） |
| 外部 Windows 命令 | `ipconfig`, `netstat`, `systeminfo`, `tasklist`, `hostname`, `whoami`, `ver`, `arp`, `route`（仅 print）, `getmac`, `where.exe`, `findstr`, `tree`, `file` | 独立验证 |

#### 安全排除项

以下 cmdlet **故意不在白名单中**：
- **`Get-Command`** — 触发模块自动加载
- **`Get-Help`** — 触发模块自动加载
- **`Select-Xml`** — XXE 攻击风险
- **`Get-WmiObject`**, **`Get-CimInstance`** — 可能发起网络请求

### 危险构造检测（11 个正则）

| 模式 | 说明 |
|------|------|
| `$()` | 子表达式 |
| `@\w+` | Splatting |
| `.\w+\s*\(` | 成员调用 |
| `$\w+\s*[+\-*/]?=` | 变量赋值 |
| `--\s*%` | Stop-parsing 符号 |
| `\\\\` | UNC 反斜杠 |
| `(?<!:)//` | UNC 正斜杠 |
| `::` | 静态方法调用 |
| `\{[^}]*\}` | 脚本块 |
| `` `[^`]*` `` | 反引号 |
| `$env:` | 环境变量访问 |
| `${` | 变量展开 |

### Git 子命令验证

与 Bash 版本一致的安全策略：

**只读子命令**（20 个）：
`status`, `diff`, `log`, `show`, `blame`, `branch`, `tag`, `remote`, `ls-files`, `stash`, `config`, `rev-parse`, `rev-list`, `shortlog`, `describe`, `cat-file`, `reflog`, `ls-tree`, `name-rev`, `merge-base`, `count-objects`

**危险标志**（6 个）：
`-c`, `--exec-path`, `--config-env`, `--git-dir`, `--work-tree`, `--attr-source`

### 验证流程

```
isReadOnlyPowerShellCommand(command)
  ├─ 空命令? → { readonly: false }
  ├─ 检查 DANGEROUS_PATTERNS（对单引号剥离后的内容）
  ├─ 检查 && / || 运算符
  ├─ 在 ; 和 | 处拆分复合命令
  ├─ 检查复合命令中是否有 CWD-changing cmdlet
  └─ 对每个子命令:
      validateSingleCommand(sub)
        ├─ 分词
        ├─ 别名解析 → 标准 cmdlet 名
        ├─ 查找 CMDLET_ALLOWLIST
        ├─ 运行 isDangerous 回调（如果有）
        ├─ 验证标志是否在 safeFlags 中
        └─ 返回 { readonly: true/false }
```

---

## 9. 模块六：AI 权限分类器

**文件**:
- `permission/classifier.ts`（388 行）— 核心分类器
- `permission/classifier-allowlist.ts`（134 行）— 白名单和危险模式
- `permission/denial-tracking.ts`（68 行）— 拒绝计数追踪
- `permission/classifier-prompt.ts`（158 行）— 提示词模板

### 功能概述

两阶段 LLM 管道，自动判断工具调用是否安全，减少手动用户审批。Fail-closed 设计确保安全。

### 分类流程

```
classify(input)
  │
  ├─ [0] 分类器未启用? → escalate (stage 0)
  ├─ [1] 用户黑名单匹配? → escalate (stage 0)
  ├─ [2] SAFE_TOOL_ALLOWLIST 匹配? → allow (stage 0)
  ├─ [3] 用户白名单匹配? → allow (stage 0)
  ├─ [4] isDangerousBashCommand? → escalate (stage 0)
  ├─ [5] isCodeExecCommand? → 标记 _codeExec（保守提示）
  ├─ [6] DenialTracker.shouldEscalate? → escalate (stage 0)
  ├─ [7] 获取分类器模型（config.model → 小模型回退）
  │     无模型? → escalate (stage 0)
  │
  ├─ [8] Stage 1: 快速分类
  │     generateObject(max_tokens=64, temp=0)
  │     ├─ allow + HIGH_RISK → 进入 Stage 2
  │     ├─ allow + normal → recordApproval, return allow
  │     └─ block → 进入 Stage 2
  │
  ├─ [9] Stage 2: 深度推理
  │     generateObject(max_tokens=2048, temp=0)
  │     ├─ allow → recordApproval, return allow
  │     └─ block → recordDenial, return escalate
  │
  └─ [catch] 任何错误 → 写入磁盘, escalate (stage 0)
```

### 安全工具白名单（14 个）

无需 LLM 调用即自动批准：

```typescript
SAFE_TOOL_ALLOWLIST = [
  "read", "glob", "grep", "list", "codesearch",
  "websearch", "webfetch", "todowrite", "question",
  "lsp", "memory_search", "memory_get",
  "memory_store", "memory_forget"
]
```

### 高风险权限（2 个）

即使 Stage 1 允许，也必须经过 Stage 2 确认：

```typescript
HIGH_RISK_PERMISSIONS = ["bash", "external_directory"]
```

### 危险 Bash 模式（16 个正则）

始终升级到用户审批：

| 模式 | 说明 |
|------|------|
| `rm -rf /~` | 递归强制删除 |
| `sudo` | 提权 |
| `chmod 777` | 过度权限 |
| `curl\|bash` | 远程代码执行 |
| `dd if=` | 磁盘操作 |
| `write to /dev/` | 设备写入 |
| `mkfs` | 格式化 |
| `shutdown/reboot/halt/poweroff` | 系统关闭 |
| `kill -9 1` | 杀 init 进程 |
| `rm/del /etc or \windows` | 系统目录删除 |
| encoded PowerShell | 编码混淆 |
| `cmd /c` | 命令执行 |
| `reg add/delete/import` | 注册表操作 |
| `format drive:` | 驱动器格式化 |
| `net user` | 用户管理 |
| `bcdedit` | 引导配置 |

### 代码执行前缀（22 个）

标记为保守分类（`_codeExec` 标志）：

```
解释器: python, python3, python2, node, deno, tsx, ruby, perl, php, lua
包运行器: npx, bunx, npm run, yarn run, pnpm run, bun run
Shell: bash, sh, zsh, fish
远程: ssh
其他: eval, exec
```

### 拒绝追踪器

| 方法 | 说明 |
|------|------|
| `configure({ consecutive, total })` | 设置自定义阈值 |
| `recordDenial()` | 增加计数器 |
| `recordApproval()` | 重置连续计数器 |
| `shouldEscalate()` | 连续 >= 3 或总计 >= 20 → 绕过分类器 |
| `reset()` | 重置所有计数器 |

### 提示词模板

#### Stage 1（快速）

- `max_tokens`: 64
- `temperature`: 0
- 输出：`allow` 或 `block`
- 包含：权限类型、模式、工具名、截断的元数据（最多 500 字符）
- 代码执行时添加警告

#### Stage 2（深度）

- `max_tokens`: 2048
- `temperature`: 0
- 输出：`reasoning` + `decision`
- 包含：Stage 1 所有数据（最多 1000 字符）、最近 5 条会话消息（每条 200 字符）
- 4 步推理指令

### 错误处理

- 任何异常 → 将错误 dump 写入 `~/.config/opencode/classifier-errors/{timestamp}.json`
- Fail-closed：错误时升级到用户审批，不会自动拒绝

---

## 10. 集成方式详解

### tool/bash.ts 中的三层安全集成

```
BashTool.execute(params, ctx)
  │
  ├─ Layer 1: Bash 安全验证
  │   if (cfg.experimental?.bash_security !== false):
  │     result = validateBashCommand(params.command)
  │     ├─ safe → bashSecurityMessage = undefined
  │     └─ unsafe → bashSecurityMessage = result.message
  │                bashSecurityIsMisparsing = result.isMisparsing
  │
  ├─ Layer 2: 只读命令自动批准
  │   if (!bashSecurityMessage && cfg.experimental?.readonly_auto_approve !== false):
  │     ps ? isReadOnlyPowerShellCommand(command)
  │        : isReadOnlyCommand(command)
  │     ├─ readonly: true → readonlyApproved = true（跳过权限提示）
  │     └─ readonly: false → readonlyApproved = false
  │
  ├─ Layer 3: 权限请求
  │   ask(ctx, scan, bashSecurityMessage, readonlyApproved)
  │   └─ 调用 Permission.ask()，包含:
  │       - 危险规则过滤
  │       - 路径安全检查
  │       - acceptEdits 快速路径
  │       - AI 分类器
  │       - 用户提示
  │
  └─ 执行命令
```

### permission/index.ts 中的决策链

详见 [第 3 节：权限决策链](#3-权限决策链完整流程)

---

## 11. 配置项汇总

所有安全功能默认启用（AI 分类器除外），可通过 `opencode.json` 的 `experimental` 配置段控制：

```json
{
  "experimental": {
    "path_safety": true,           // 路径安全保护（默认: true）
    "bash_security": true,         // Bash 命令安全验证（默认: true）
    "readonly_auto_approve": true   // 只读命令自动批准（默认: true）
  },
  "classifier": {
    "enabled": false,              // AI 权限分类器（默认: false，需手动启用）
    "timeout": 5000,               // 分类器超时（毫秒）
    "model": "provider/model-id"   // 分类器使用的模型（如 "anthropic/claude-haiku"）
  }
}
```

---

## 12. 文件清单

### 新增文件（11 个）

| 文件 | 行数 | 模块 |
|------|------|------|
| `security/path-safety.ts` | 241 | 路径安全保护 |
| `security/bash-patterns.ts` | 135 | Bash 安全模式常量 |
| `security/bash-security.ts` | 656 | 16 个安全验证器 |
| `security/readonly-commands.ts` | 1444 | Bash 只读命令自动批准 |
| `security/readonly-powershell.ts` | 891 | PowerShell 只读命令自动批准 |
| `permission/dangerous-rules.ts` | 142 | 危险权限规则过滤 |
| `permission/classifier-allowlist.ts` | 134 | 安全工具白名单 |
| `permission/denial-tracking.ts` | 68 | 拒绝计数追踪 |
| `permission/classifier-prompt.ts` | 158 | 分类器提示词模板 |
| `permission/classifier.ts` | 388 | 核心分类器 |
| `test/security/dangerous-rules.test.ts` | — | 危险规则测试 |

### 修改文件（6 个）

| 文件 | 修改内容 |
|------|---------|
| `permission/index.ts` | 路径安全 + Bash 安全 + 危险规则过滤 + 分类器集成 |
| `permission/classifier-allowlist.ts` | Windows 危险命令 |
| `session/prompt.ts` | Classifier.reset() 调用 |
| `tool/bash.ts` | Bash 安全验证 + 只读命令检查（Bash + PowerShell） |
| `config/config.ts` | experimental 配置项 + classifier 配置段 |
| `permission/classifier.ts` | HIGH_RISK 权限逻辑 |

### 总代码量

约 **5,157 行**新增安全代码（不含测试和注释空行）

---

## 13. 尚未移植的模块

根据 Claude Code 的完整安全体系对比，以下模块尚未移植：

| 模块 | 说明 | 优先级 |
|------|------|--------|
| **沙箱隔离** | 文件系统 + 网络沙箱，限制写入目录和网络访问 | 高 |
| **策略系统** | 企业级远程策略、托管设置、环境变量安全 | 中 |
| **Hook 系统** | PreToolUse/PostToolUse/PermissionRequest 等事件钩子 | 中 |
| **Unicode 净化** | NFKC 标准化、零宽字符移除、递归净化 | 中 |
| **PowerShell AST 分析** | `Invoke-Expression` 检测、COM 对象、下载摇篮检测 | 高 |
| **提示注入防护** | 完整的输入净化管道 | 中 |

---

> **文档生成日期**: 2026-04-13
> **基于代码版本**: OpenCode v1.1.0 (commit: 93108d7ca)
