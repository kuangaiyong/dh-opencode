# Claude Code 安全机制核心特性及实现方案

## 一、架构总览 — 多层纵深防御

Claude Code 的安全体系分为 **6 大防御层**：

```
┌─────────────────────────────────────────────────┐
│  Layer 6: 策略系统（企业级）                        │
│  Layer 5: 沙箱隔离（文件系统 + 网络）                │
│  Layer 4: AI 分类器（2 阶段自动决策）                │
│  Layer 3: 命令安全（23 个 Bash 检查器 + PS AST 分析）│
│  Layer 2: 权限评估流水线（deny→ask→allow）           │
│  Layer 1: Unicode 净化 + 输入验证                   │
└─────────────────────────────────────────────────┘
```

---

## 二、安全模块文件清单

| 模块 | 文件路径 | 核心职责 |
|------|----------|----------|
| **权限类型定义** | `types\permissions.ts` | 权限模式、行为、规则、决策的类型系统 |
| **权限核心引擎** | `utils\permissions\permissions.ts` | 权限评估流水线：deny→ask→tool.check→bypass→allow |
| **权限规则解析** | `utils\permissions\permissionRuleParser.ts` | 权限规则字符串解析（Tool(content)格式） |
| **权限规则加载** | `utils\permissions\permissionsLoader.ts` | 从磁盘各来源加载权限规则，企业策略强制 |
| **权限模式管理** | `utils\permissions\permissionSetup.ts` | 权限模式初始化、模式转换、危险权限剥离 |
| **危险模式检测** | `utils\permissions\dangerousPatterns.ts` | Bash/PowerShell 危险命令前缀模式 |
| **权限解释器** | `utils\permissions\permissionExplainer.ts` | AI 驱动的权限风险解释（LOW/MEDIUM/HIGH） |
| **拒绝追踪** | `utils\permissions\denialTracking.ts` | 连续/累计拒绝计数，回退到手动确认 |
| **YOLO 分类器** | `utils\permissions\yoloClassifier.ts` | Auto 模式下的 AI 动作分类决策 |
| **分类器决策** | `utils\permissions\classifierDecision.ts` | 分类器决策逻辑（2 阶段 XML） |
| **Bash 安全检查** | `tools\BashTool\bashSecurity.ts` | Bash 命令注入检测、heredoc 验证、混淆检测 |
| **Bash 权限** | `tools\BashTool\bashPermissions.ts` | Bash 工具权限评估（前缀匹配、通配符、AST 分析） |
| **Bash 路径验证** | `tools\BashTool\pathValidation.ts` | 文件路径约束验证、危险删除路径检测 |
| **Bash 沙箱判断** | `tools\BashTool\shouldUseSandbox.ts` | 判断命令是否应在沙箱中执行 |
| **PowerShell 安全** | `tools\PowerShellTool\powershellSecurity.ts` | PowerShell AST 级安全分析 |
| **PowerShell 权限** | `tools\PowerShellTool\powershellPermissions.ts` | PowerShell 工具权限评估 |
| **PowerShell 危险命令** | `utils\powershell\dangerousCmdlets.ts` | PS 危险 cmdlet 常量集合 |
| **沙箱适配器** | `utils\sandbox\sandbox-adapter.ts` | @anthropic-ai/sandbox-runtime 适配层 |
| **Unicode 净化** | `utils\sanitization.ts` | Unicode 隐藏字符攻击防御（ASCII Smuggling） |
| **策略限制** | `services\policyLimits\index.ts` | 组织级策略限制 API |
| **策略限制类型** | `services\policyLimits\types.ts` | 策略响应 Schema 定义 |
| **托管环境管理** | `utils\managedEnv.ts` | 安全环境变量应用、项目设置信任隔离 |
| **托管环境常量** | `utils\managedEnvConstants.ts` | 安全/危险环境变量白名单 |
| **远程设置安全** | `services\remoteManagedSettings\securityCheck.tsx` | 远程托管设置安全审查对话框 |
| **权限验证** | `utils\settings\permissionValidation.ts` | 权限规则格式验证 |
| **安全审查命令** | `commands\security-review.ts` | 代码安全审查 slash command |
| **权限日志** | `hooks\toolPermission\permissionLogging.ts` | 权限决策遥测和分析日志 |
| **群组权限同步** | `utils\swarm\permissionSync.ts` | 多 Agent 群组权限请求转发 |
| **Hook Schema** | `schemas\hooks.ts` | Hook 类型定义（PreToolUse/PostToolUse/PermissionRequest） |

---

## 三、权限系统架构

### 3.1 权限模式

| 模式 | 说明 | 安全级别 |
|------|------|----------|
| `default` | 默认模式，所有工具需要用户确认 | 最高 |
| `plan` | 计划模式，只读操作自动允许 | 高 |
| `acceptEdits` | 接受编辑模式，文件编辑自动允许 | 中 |
| `dontAsk` | 不询问模式，ask 自动转为 deny | 中 |
| `auto` | 自动模式，AI 分类器决定允许/拒绝 | 中 |
| `bypassPermissions` | 绕过所有权限检查 | 最低（受控） |

### 3.2 权限评估流水线（`hasPermissionsToUseTool`）

权限检查按以下严格顺序执行：

```
步骤 1a: 全局 deny 规则匹配 → deny
步骤 1b: 全局 ask 规则匹配 → ask (沙箱自动允许例外)
步骤 1c: 工具自身 checkPermissions() → deny/ask/passthrough
步骤 1d: 工具实现拒绝 → deny
步骤 1e: 工具需要用户交互 + ask → ask (bypass 模式下也强制)
步骤 1f: 内容级 ask 规则 → ask (bypass 模式下也强制)
步骤 1g: 安全检查（.git/, .claude/ 等）→ ask (bypass 模式下也强制)
步骤 2a: bypassPermissions 模式 → allow
步骤 2b: 全局 allow 规则匹配 → allow
步骤 3:  passthrough → ask
步骤 4:  模式后处理：
         - dontAsk: ask → deny
         - auto: AI 分类器评估
         - shouldAvoidPermissionPrompts: 运行 hooks 后 auto-deny
```

**关键特性**：
- **Bypass 模式下的硬墙**：步骤 1d/1e/1f/1g 的检查即使在 `bypassPermissions` 模式下也强制执行
- **安全检查**（步骤 1g）：对 `.git/`、`.claude/`、`.vscode/`、shell 配置文件的访问，即使是 bypass 模式也必须提示用户
- **分类器 Approvable 标记**：部分安全检查（如敏感文件路径）可由分类器评估，但 Windows 路径绕过尝试和跨机器桥接消息绝对不可由分类器自动批准

### 3.3 权限规则系统

**规则格式**：`ToolName(ruleContent)` 或 `ToolName`

- `Bash` — 允许所有 Bash 命令
- `Bash(git *)` — 允许所有 git 开头的命令
- `Bash(npm run:*)` — 允许 npm run 前缀命令
- `Edit(**/*.ts)` — 允许编辑所有 .ts 文件
- `mcp__server1__*` — 允许 MCP server1 的所有工具

**规则来源优先级**（从高到低）：
1. `policySettings`（企业管理员）
2. `flagSettings`（CLI flag）
3. `userSettings`（~/.claude/settings.json）
4. `projectSettings`（.claude/settings.json）
5. `localSettings`（.claude/settings.local.json）
6. `cliArg`（--allowed-tools）
7. `session`（会话临时）
8. `command`（命令来源）

---

## 四、命令安全

### 4.1 Bash 安全检查（`bashSecurity.ts`）— 23 个安全检查器

| 检查 ID | 检查名称 | 描述 |
|---------|----------|------|
| 1 | INCOMPLETE_COMMANDS | 检测以 tab、flag、操作符开头的片段 |
| 2 | JQ_SYSTEM_FUNCTION | jq 的 system() 函数（执行任意代码） |
| 3 | JQ_FILE_ARGUMENTS | jq 的 -f/--from-file 等危险 flag |
| 4 | OBFUSCATED_FLAGS | ANSI-C 引用($'...')、空引号拼接等混淆 |
| 5 | SHELL_METACHARACTERS | 引号中的 ;、|、& 字符 |
| 6 | DANGEROUS_VARIABLES | 重定向/管道中的 $VAR |
| 7 | NEWLINES | 换行符分隔的多命令 |
| 8 | COMMAND_SUBSTITUTION | $()、${}、反引号、进程替换 <() >() |
| 9 | INPUT_REDIRECTION | < 重定向（可能读取敏感文件） |
| 10 | OUTPUT_REDIRECTION | > 重定向（可能写入任意文件） |
| 11 | IFS_INJECTION | $IFS 变量使用（绕过正则验证） |
| 12 | GIT_COMMIT_SUBSTITUTION | git commit -m 中的命令替换 |
| 13 | PROC_ENVIRON_ACCESS | /proc/*/environ 访问（泄露环境变量） |
| 14 | MALFORMED_TOKEN_INJECTION | 不平衡分隔符 + 命令分隔符组合 |
| 15 | BACKSLASH_ESCAPED_WHITESPACE | 反斜杠转义空白字符 |
| 16 | BRACE_EXPANSION | 大括号扩展 {a,b} |
| 17 | CONTROL_CHARACTERS | 控制字符 |
| 18 | UNICODE_WHITESPACE | Unicode 空白字符隐藏内容 |
| 19 | MID_WORD_HASH | 词中 # 字符（shell 注释混淆） |
| 20 | ZSH_DANGEROUS_COMMANDS | zsh 特有危险命令（zmodload、emulate 等） |
| 21 | BACKSLASH_ESCAPED_OPERATORS | 反斜杠转义操作符 |
| 22 | COMMENT_QUOTE_DESYNC | 注释/引号不同步 |
| 23 | QUOTED_NEWLINE | 引号中的换行 |

**特殊安全机制**：
- **安全 Heredoc 识别**：`$(cat <<'DELIM'...DELIM)` 模式可以自动允许（带严格验证）
- **回车符检测**：`\r` 导致的 shell-quote/bash 解析差异攻击
- **Zsh 危险命令**：`zmodload`、`emulate`、`zpty`、`ztcp` 等 24 个内置命令
- **解析器差异防御**：当命令被解析器错误解析时，返回 `isBashSecurityCheckForMisparsing` 标记

### 4.2 PowerShell 安全检查（`powershellSecurity.ts`）

基于 AST 的安全分析，包括：

- **Invoke-Expression (iex) 检测**
- **动态命令名检测**（`& ('iex','x')[0]` 等）
- **Start-Process 检测**（Verb RunAs 提权）
- **COM 对象检测**（WScript.Shell 等）
- **下载摇篮检测**（Invoke-WebRequest + Invoke-Expression 组合）
- **ScriptBlock 注入检测**
- **WMI/CIM 进程生成检测**（Win32_Process.Create）
- **运行时状态篡改检测**（Set-Alias、Set-Variable）

### 4.3 危险命令模式

**跨平台代码执行入口**（`dangerousPatterns.ts`）：
```
python, python3, node, deno, ruby, perl, php, lua,
npx, bunx, npm run, bash, sh, ssh, eval, exec, env, xargs, sudo
```

**PowerShell 特有危险 cmdlets**：
```
Invoke-Expression (iex), Start-Process, Start-Job, New-PSSession,
Enter-PSSession, Add-Type, New-Object, Import-Module, Invoke-WmiMethod
```

---

## 五、文件安全

### 5.1 路径验证（`pathValidation.ts`）

**支持的路径命令**：cd, ls, find, mkdir, touch, rm, rmdir, mv, cp, cat, head, tail, sort, uniq, wc, cut, paste, column, tr, file, stat, diff, awk, strings, hexdump, od, base64, nl, grep, rg, sed, git, jq, sha256sum, sha1sum, md5sum

**安全机制**：
- 所有路径必须在工作目录范围内
- **`--` 分隔符处理**：正确识别 POSIX `--` 后的位置参数
- **危险删除路径检测**：`rm -rf /` 等操作始终需要明确批准
- **cd + 写操作复合命令**：防止通过 cd 改变工作目录后绕过路径检查
- **进程替换检测**：`>(tee .git/config)` 等进程替换绕过
- **Shell 展开语法**：路径中包含 $VAR 或 %VAR% 时需要手动批准

### 5.2 输出重定向验证

- 所有 `>` 和 `>>` 重定向目标都在工作目录范围内验证
- `/dev/null` 始终安全
- 复合命令中 cd + 重定向的组合被阻止

---

## 六、沙箱系统（`sandbox-adapter.ts`）

### 6.1 沙箱配置

| 维度 | 控制内容 |
|------|----------|
| **文件系统** | 只允许写入当前目录 + 临时目录；保护 settings.json、`.claude/skills/`、裸 Git 仓库 |
| **网络** | 域名白名单/黑名单；控制 Unix 域套接字和本地绑定 |
| **命令后清理** | `cleanupAfterCommand()` 清除沙箱执行期间可能植入的文件 |
| **平台支持** | macOS、Linux、WSL2（WSL1 不支持）|

**关键**: `autoAllowBashIfSandboxed=true` 时，沙箱内的命令自动允许。

### 6.2 沙箱安全特性

- **设置文件保护**：所有来源的 settings.json 在沙箱内不可写，防止沙箱逃逸
- **裸 Git 仓库防护**：防止攻击者通过 `HEAD + objects/ + refs/` 伪造 Git 仓库配置 core.fsmonitor
- **Worktree 支持**：自动检测 Git worktree 并允许主仓库 .git 目录写入
- **命令后清理**：`cleanupAfterCommand()` 清除可能在沙箱执行期间植入的文件
- **平台限制**：支持 macOS、Linux、WSL2（WSL1 不支持）

### 6.3 沙箱与权限交互

- **autoAllowBashIfSandboxed**：当沙箱启用时，自动允许沙箱内的 Bash 命令
- **excludedCommands**：指定不从沙箱排除的命令（如 bazel）
- **dangerouslyDisableSandbox**：单条命令禁用沙箱（需策略允许）

---

## 七、AI 分类器（Auto 模式）

### 7.1 决策流程

1. **acceptEdits 快速路径**：如果工具在 `acceptEdits` 模式下会被允许，跳过分类器直接批准
2. **安全工具白名单**：已知安全的工具直接批准
3. **AI 分类器评估**：2 阶段 XML 分类器评估动作安全性
4. **拒绝限制**：连续拒绝 3 次或累计拒绝 20 次后，回退到手动确认

### 7.2 铁门机制

- 分类器不可用时，`tengu_iron_gate_closed` 开关决定 fail-closed（拒绝）还是 fail-open（回退手动）
- 连续拒绝超限时，无头模式下直接 AbortError
- 铁门缓存刷新时间：30 分钟

---

## 八、策略系统（企业级）

### 8.1 策略限制（`policyLimits/`）

- 从 API 获取组织级策略，控制功能开关
- 支持任意 `key → { allowed: boolean }` 策略
- **Fail-open**：API 不可用时默认允许（`allow_product_feedback` 例外）
- **ETag 缓存**：304 Not Modified 使用缓存
- **后台轮询**：每小时检查策略更新

### 8.2 托管设置安全

**`allowManagedPermissionRulesOnly`**：
- 启用时，只尊重来自 `policySettings` 的权限规则
- 清除所有非策略来源的 allow/deny/ask 规则
- 隐藏 "always allow" 选项

**`shouldAllowManagedSandboxDomainsOnly`**：
- 启用时，只使用策略设置中的网络域名白名单

### 8.3 环境变量安全（`managedEnv.ts`）

**信任模型**：
- **可信来源**（userSettings、flagSettings、policySettings）：所有环境变量可应用
- **项目级来源**（projectSettings、localSettings）：只应用 `SAFE_ENV_VARS` 白名单中的变量

**危险环境变量**（不在白名单中）：
- `ANTHROPIC_BASE_URL`（重定向到攻击者服务器）
- `HTTP_PROXY`、`HTTPS_PROXY`（流量劫持）
- `NODE_TLS_REJECT_UNAUTHORIZED`（TLS 验证绕过）
- `ANTHROPIC_API_KEY`（API 密钥替换）

**Shell 设置安全**（`DANGEROUS_SHELL_SETTINGS`）：
- `apiKeyHelper`、`awsAuthRefresh`、`statusLine` 等可执行任意代码的设置

### 8.4 远程托管设置安全审查（`securityCheck.tsx`）

当远程 API 推送包含危险设置的新配置时：
- 显示阻塞式安全审查对话框
- 用户可批准或拒绝
- 仅在交互模式下显示

---

## 九、提示注入防护

### 9.1 Unicode 净化（`sanitization.ts`）

防御 ASCII Smuggling 和 Hidden Prompt Injection 攻击（HackerOne #3086545）：

**净化策略**：
1. **NFKC 标准化**：处理组合字符序列
2. **危险 Unicode 类别移除**：
   - `\p{Cf}`（格式字符）
   - `\p{Co}`（私用区字符）
   - `\p{Cn}`（未分配字符）
3. **显式范围移除**：
   - 零宽空格（U+200B-200F）
   - 方向格式字符（U+202A-202E）
   - 字节序标记（U+FEFF）
   - BMP 私用区（U+E000-F8FF）
4. **迭代净化**：最多 10 次迭代，超限抛出异常
5. **递归净化**：支持字符串、数组、对象的深度净化

### 9.2 命令注入防护

**Bash 层面**：
- 23 个安全检查器覆盖所有已知注入向量
- 混淆检测（ANSI-C 引用、空引号拼接、多引号）
- 解析器差异防御（shell-quote vs bash 的不同行为）

**PowerShell 层面**：
- AST 级别的安全分析
- 动态命令名检测（allowlist StringConstant 类型）
- 替代参数前缀处理（/、en-dash、em-dash）

---

## 十、Hook 系统

### 10.1 Hook 类型

| Hook 事件 | 触发时机 |
|-----------|----------|
| `PreToolUse` | 工具执行前 |
| `PostToolUse` | 工具执行后 |
| `PermissionRequest` | 权限请求时（无头 Agent 使用） |
| `Notification` | 通知触发时 |
| `Stop` | Agent 停止时 |

### 10.2 Hook 实现类型

- **command**：执行 Shell 命令
- **prompt**：LLM 提示评估
- **http**：HTTP POST 请求
- **agent**：Agent 验证器

### 10.3 Hook 安全特性

- **条件过滤**（`if` 字段）：使用权限规则语法过滤
- **超时控制**：每个 Hook 可配置超时
- **一次性 Hook**（`once`）：执行后自动移除
- **异步 Hook**（`async`）：不阻塞主流程

---

## 十一、群组权限同步（Swarm Permission Sync）

### 11.1 架构

多 Agent 群组中的权限转发机制：
- Worker Agent → Leader Agent 的权限请求
- Leader Agent → Worker Agent 的权限响应

### 11.2 通信机制

- **文件系统邮箱**：基于 `~/.claude/teams/{team}/permissions/` 目录
- **锁定机制**：文件锁保证原子操作
- **沙箱权限转发**：网络访问请求转发到 Leader

---

## 十二、安全流程总结

### 完整权限检查流程

```
用户操作 → 工具调用
    ↓
hasPermissionsToUseTool()
    ↓
[1a] deny 规则检查 ────→ DENY
[1b] ask 规则检查 ────→ ASK (sandbox auto-allow 例外)
[1c] tool.checkPermissions()
    ├── bashSecurity (23个检查器)
    ├── pathValidation (路径约束)
    ├── readOnlyValidation (只读验证)
    ├── sedValidation (sed 安全)
    └── modeValidation (模式验证)
[1d] 工具拒绝 ─────────→ DENY
[1e] 需要用户交互 ──────→ ASK (bypass-immune)
[1f] 内容级 ask 规则 ───→ ASK (bypass-immune)
[1g] 安全检查 ──────────→ ASK (bypass-immune)
    ↓
[2a] bypassPermissions ─→ ALLOW
[2b] allow 规则匹配 ───→ ALLOW
[3]  passthrough → ASK
    ↓
模式后处理:
    - dontAsk → DENY
    - auto → AI Classifier → ALLOW/DENY
    - headless → Hook check → DENY (fallback)
```

### 关键配置默认值

| 配置 | 默认值 | 说明 |
|------|--------|------|
| 沙箱启用 | `false` | 用户需手动启用 |
| autoAllowBashIfSandboxed | `true` | 沙箱内自动允许 Bash |
| allowUnsandboxedCommands | `true` | 允许非沙箱命令 |
| failIfUnavailable | `false` | 沙箱不可用时不失败 |
| 连续拒绝上限 | `3` | 回退手动确认 |
| 累计拒绝上限 | `20` | 回退手动确认 |
| 分类器铁门刷新 | `30分钟` | iron_gate 缓存时间 |
| 策略轮询间隔 | `1小时` | 后台策略检查 |
| Unicode 净化迭代上限 | `10` | 防无限循环 |

---

## 十三、与 OpenCode 移植版本对比

### 已移植（Layer 2-4 部分）

| 模块 | OpenCode 对应文件 | 状态 |
|------|-------------------|------|
| 路径安全检查 | `security/path-safety.ts` | 已完成 |
| Bash 命令安全（16 个验证器） | `security/bash-security.ts` + `security/bash-patterns.ts` | 已完成 |
| 只读命令自动批准（Bash + PowerShell） | `security/readonly-commands.ts` + `security/readonly-powershell.ts` | 已完成 |
| 危险权限规则过滤 | `permission/dangerous-rules.ts` | 已完成 |
| AI 权限分类器（2 阶段） | `permission/classifier.ts` | 已完成 |
| 分类器白名单 | `permission/classifier-allowlist.ts` | 已完成 |
| 拒绝追踪 | `permission/denial-tracking.ts` | 已完成 |

### 待移植模块

| 优先级 | 模块 | 说明 |
|--------|------|------|
| P0 | Unicode 净化（`sanitization.ts`） | 防御 ASCII Smuggling 和隐藏提示注入 |
| P0 | 权限规则解析器（`permissionRuleParser.ts`） | 支持 Tool(content) 格式规则 |
| P1 | 沙箱系统（`sandbox-adapter.ts`） | 文件系统 + 网络隔离 |
| P1 | Hook 系统（`hooks.ts`） | PreToolUse/PostToolUse/PermissionRequest |
| P1 | PowerShell AST 安全分析 | AST 级别的深度安全检查 |
| P2 | 策略系统（`policyLimits/`） | 企业级组织策略 |
| P2 | 环境变量安全（`managedEnv.ts`） | 项目级配置信任隔离 |
| P2 | 远程设置安全审查 | 推送配置时的阻塞式审查 |
| P3 | 群组权限同步（Swarm） | 多 Agent 权限转发 |
| P3 | 权限解释器 | AI 驱动的风险解释 |

---

**分析日期**: 2026-04-11  
**来源**: Claude Code (`C:\opencode\dh-opencode\claude-code`)  
**目标项目**: OpenCode (`C:\opencode\dh-opencode\opencode`)
