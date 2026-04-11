# Hermes Agent 自动进化体系移植至 OpenCode — 综合分析报告

> **日期**: 2026-04-11  
> **分支**: `evolution-hermes`（基于 `master`）  
> **目标**: 将 Hermes Agent 的自动进化体系移植到 OpenCode，不破坏现有模块功能

---

## 一、两个系统的架构对比

| 维度 | Hermes Agent (Python) | OpenCode (TypeScript/Effect) |
|------|----------------------|------------------------------|
| **Skill 系统** | 完整的 CRUD + 安全扫描 + Hub 市场 + 自动创建/改进 | 只读发现 + 加载（`skill/index.ts` 277 行） |
| **Memory 系统** | 内建 + 外部 Provider 编排 + nudge 自动触发 | 完整实现（hybrid search, embedding, 去重, consolidate, 356 行） |
| **Nudge 机制** | 迭代计数器 → 阈值触发 → 守护线程后台审查 | **不存在** |
| **Context 压缩** | 5 阶段算法（prune→boundary→LLM summary→assemble→fix） | prune + LLM summary（`compaction.ts` 548 行） |
| **RL 训练** | Atropos 集成 + 批量轨迹生成 + 压缩 | **不存在** |
| **自优化提示词** | 模型特定引导（OpenAI/Google/工具使用强制） | 基础 provider-specific 提示词（`system.ts` 路由到 .txt） |
| **安全** | `skills_guard.py` 60+ 威胁模式 | 6 层安全体系（已移植） |
| **工具注册** | 动态加载，Python dict | `ToolRegistry` Effect Service，`Tool.define()` |
| **Agent 定义** | 单 `AIAgent` 类（9000+ 行） | `Agent.Info` Zod schema + 多 agent（build/plan/explore/...） |
| **事件系统** | 回调 + 线程 | Effect PubSub (`Bus`) |
| **配置** | YAML + env | JSONC (`Config.Info` Zod schema) |

---

## 二、Hermes 自动进化体系详解

### 2.1 Nudge 机制 — 核心驱动引擎

Nudge 是 Hermes 自动进化的心脏。它通过迭代计数器定期触发后台审查，让 Agent 在无人干预的情况下自动保存有价值的经验和记忆。

#### 2.1.1 计数器初始化

**文件**: `run_agent.py`

| 变量 | 行号 | 默认值 | 说明 |
|---|---|---|---|
| `self._memory_nudge_interval` | 1109 | `10` | 每隔多少轮触发 memory 审查 |
| `self._skill_nudge_interval` | 1209 | `10` | 每隔多少次工具迭代触发 skill 审查 |
| `self._turns_since_memory` | 1111 | `0` | Memory 轮次计数器 |
| `self._iters_since_skill` | 1112 | `0` | Skill 迭代计数器 |

配置覆盖：
- 行 1118: `self._memory_nudge_interval = int(mem_config.get("nudge_interval", 10))`
- 行 1212: `self._skill_nudge_interval = int(skills_config.get("creation_nudge_interval", 10))`

#### 2.1.2 计数器递增与阈值检查

**Memory nudge**（行 7481–7488）:

```python
_should_review_memory = False
if (self._memory_nudge_interval > 0
        and "memory" in self.valid_tool_names
        and self._memory_store):
    self._turns_since_memory += 1
    if self._turns_since_memory >= self._memory_nudge_interval:
        _should_review_memory = True
        self._turns_since_memory = 0
```

**Skill nudge 递增**（行 7719–7723）:

```python
if (self._skill_nudge_interval > 0
        and "skill_manage" in self.valid_tool_names):
    self._iters_since_skill += 1
```

**Skill nudge 阈值检查**（行 9952–9958）:

```python
_should_review_skills = False
if (self._skill_nudge_interval > 0
        and self._iters_since_skill >= self._skill_nudge_interval
        and "skill_manage" in self.valid_tool_names):
    _should_review_skills = True
    self._iters_since_skill = 0
```

**计数器重置**（当工具被实际使用时，行 6587–6591 + 行 6808–6812）:

```python
if function_name == "memory":
    self._turns_since_memory = 0
elif function_name == "skill_manage":
    self._iters_since_skill = 0
```

重要注释（行 7435–7437）:

```python
# NOTE: _turns_since_memory and _iters_since_skill are NOT reset here.
# They are initialized in __init__ and must persist across run_conversation
# calls so that nudge logic accumulates correctly in CLI mode.
```

#### 2.1.3 后台审查触发（行 9970–9980）

```python
if final_response and not interrupted and (_should_review_memory or _should_review_skills):
    try:
        self._spawn_background_review(
            messages_snapshot=list(messages),
            review_memory=_should_review_memory,
            review_skills=_should_review_skills,
        )
    except Exception:
        pass  # Background review is best-effort
```

#### 2.1.4 审查提示词

**Memory 审查提示词**（行 1919–1928）:

```
Review the conversation above and consider saving to memory if appropriate.

Focus on:
1. Has the user revealed things about themselves — their persona, desires,
   preferences, or personal details worth remembering?
2. Has the user expressed expectations about how you should behave, their work
   style, or ways they want you to operate?

If something stands out, save it using the memory tool.
If nothing is worth saving, just say 'Nothing to save.' and stop.
```

**Skill 审查提示词**（行 1930–1938）:

```
Review the conversation above and consider saving or updating a skill if appropriate.

Focus on: was a non-trivial approach used to complete a task that required trial
and error, or changing course due to experiential findings along the way, or did
the user expect or desire a different method or outcome?

If a relevant skill already exists, update it with what you learned.
Otherwise, create a new skill if the approach is reusable.
If nothing is worth saving, just say 'Nothing to save.' and stop.
```

**合并审查提示词**（行 1940–1952）— 当 memory 和 skill 同时触发时使用:

```
Review the conversation above and consider two things:

**Memory**: Has the user revealed things about themselves — their persona,
desires, preferences, or personal details? Has the user expressed expectations
about how you should behave, their work style, or ways they want you to operate?
If so, save using the memory tool.

**Skills**: Was a non-trivial approach used to complete a task that required trial
and error, or changing course due to experiential findings along the way, or did
the user expect or desire a different method or outcome? If a relevant skill
already exists, update it. Otherwise, create a new one if the approach is reusable.

Only act if there's something genuinely worth saving.
If nothing stands out, just say 'Nothing to save.' and stop.
```

#### 2.1.5 后台审查执行器（行 1954–2053）

`_spawn_background_review()` 是完整的后台审查机制：

```python
def _spawn_background_review(
    self,
    messages_snapshot: List[Dict],
    review_memory: bool = False,
    review_skills: bool = False,
) -> None:
    """Spawn a background thread to review the conversation for memory/skill saves.

    Creates a full AIAgent fork with the same model, tools, and context as the
    main session. The review prompt is appended as the next user turn in the
    forked conversation. Writes directly to the shared memory/skill stores.
    Never modifies the main conversation history or produces user-visible output.
    """
    import threading

    # Pick the right prompt based on which triggers fired
    if review_memory and review_skills:
        prompt = self._COMBINED_REVIEW_PROMPT
    elif review_memory:
        prompt = self._MEMORY_REVIEW_PROMPT
    else:
        prompt = self._SKILL_REVIEW_PROMPT

    def _run_review():
        import contextlib, os as _os
        review_agent = None
        try:
            with open(_os.devnull, "w") as _devnull, \
                 contextlib.redirect_stdout(_devnull), \
                 contextlib.redirect_stderr(_devnull):
                review_agent = AIAgent(
                    model=self.model,
                    max_iterations=8,
                    quiet_mode=True,
                    platform=self.platform,
                    provider=self.provider,
                )
                # 共享存储但禁用递归 nudge
                review_agent._memory_store = self._memory_store
                review_agent._memory_enabled = self._memory_enabled
                review_agent._user_profile_enabled = self._user_profile_enabled
                review_agent._memory_nudge_interval = 0     # 防止递归
                review_agent._skill_nudge_interval = 0      # 防止递归

                review_agent.run_conversation(
                    user_message=prompt,
                    conversation_history=messages_snapshot,
                )

            # 扫描审查 agent 的消息，提取成功的操作并汇总
            actions = []
            for msg in getattr(review_agent, "_session_messages", []):
                if not isinstance(msg, dict) or msg.get("role") != "tool":
                    continue
                try:
                    data = json.loads(msg.get("content", "{}"))
                except (json.JSONDecodeError, TypeError):
                    continue
                if not data.get("success"):
                    continue
                message = data.get("message", "")
                target = data.get("target", "")
                if "created" in message.lower():
                    actions.append(message)
                elif "updated" in message.lower():
                    actions.append(message)
                # ... 更多匹配模式

            if actions:
                summary = " · ".join(dict.fromkeys(actions))
                self._safe_print(f"  💾 {summary}")

        except Exception as e:
            logger.debug("Background memory/skill review failed: %s", e)
        finally:
            if review_agent is not None:
                try:
                    review_agent.close()
                except Exception:
                    pass

    t = threading.Thread(target=_run_review, daemon=True, name="bg-review")
    t.start()
```

关键设计要点：
- **守护线程** — 不阻塞主会话
- **Fork AIAgent** — 共享模型和存储，但独立上下文
- **递归保护** — 审查 agent 的 nudge_interval 设为 0
- **max_iterations=8** — 限制审查 agent 的工具调用轮数
- **quiet_mode=True** — 不产生可见输出
- **Best-effort** — 失败静默忽略

### 2.2 Skill 系统

#### 2.2.1 Skill CRUD（`tools/skill_manager_tool.py`，762 行）

核心操作：
- **create** — 创建新技能，支持 frontmatter（name/description/version/category/tags）
- **edit** — 替换整个技能内容
- **patch** — 部分更新（JSON Patch 风格）
- **delete** — 删除技能文件
- 安全特性：原子写入（写临时文件 → rename）、frontmatter 验证、缓存刷新

#### 2.2.2 Skill 安全扫描（`tools/skills_guard.py`，977 行）

60+ 威胁模式检测：
- **注入检测** — system prompt injection, instruction override
- **权限提升** — 尝试修改 permission, auth 配置
- **数据外泄** — 尝试读取 env, secrets, credentials
- **代码执行** — eval, exec, subprocess 滥用
- **文件系统攻击** — 路径遍历, 符号链接攻击

#### 2.2.3 Skill Hub 市场（`tools/skills_hub.py`，2775 行）

7 个多源适配器：
1. GitHub Repository Adapter
2. skills.sh Registry Adapter
3. Well-Known URL Adapter
4. Local Directory Adapter
5. Git Repository Adapter
6. HTTP Archive Adapter
7. Custom Manifest Adapter

功能：搜索 → 浏览 → 安装 → 更新 → 卸载

#### 2.2.4 Skill 提示词注入（`agent/prompt_builder.py`，行 164-171）

```python
SKILLS_GUIDANCE = (
    "You have access to specialized skills that enhance your capabilities.\n"
    "Skills are loaded automatically based on context and can be viewed with the skill tool.\n"
    "To create or update skills after learning something valuable, use skill_manage.\n"
    "Skills are Markdown files with YAML frontmatter (name, description, version, etc.)."
)
```

技能索引注入（行 533-751）：`build_skills_system_prompt()` 生成包含技能名称、描述、路径的索引段落，注入到系统提示词中。

### 2.3 Memory 系统

#### 2.3.1 MemoryManager（`agent/memory_manager.py`，362 行）

`MemoryManager` 编排内建 + 外部 Provider：
- `initialize()` → `prefetch_all()` → `sync_turn()` → `on_session_end()` → `shutdown_all()`
- `handle_tool_call()` — 路由工具调用到正确的 provider
- `on_pre_compress()` — 压缩前保存重要上下文

#### 2.3.2 MemoryProvider（`agent/memory_provider.py`，231 行）

抽象基类定义生命周期接口：
```python
class MemoryProvider(ABC):
    def initialize(self, agent_config) -> None
    def prefetch(self) -> None
    def sync_turn(self, messages) -> None
    def on_session_end(self) -> None
    def shutdown(self) -> None
```

### 2.4 Context 压缩

#### 5 阶段压缩算法（`agent/context_compressor.py`，766 行）

1. **Prune old tool results** — 移除旧的工具输出（保留最近 40K token 的工具结果）
2. **Determine head/tail boundaries** — 识别重要消息边界（系统提示 + 最近对话）
3. **Generate structured LLM summary** — 生成结构化摘要（限制 12K token 上限，摘要比例 20%）
4. **Assemble messages** — 头部 + 摘要 + 尾部重组
5. **Fix tool pairs** — 确保 assistant tool_call 和 tool response 配对完整

关键常量：
- `threshold_percent = 0.50` — 在上下文窗口 50% 时触发压缩
- `_SUMMARY_RATIO = 0.20` — 摘要占原始内容的 20%
- `_SUMMARY_TOKENS_CEILING = 12000` — 摘要最大 token 数

### 2.5 RL 训练管线（不建议移植）

- `rl_cli.py`（446 行）— RL 训练 CLI
- `tools/rl_training_tool.py`（1396 行）— 10 个 RL 操作
- `batch_runner.py`（1287 行）— 批量轨迹生成
- `trajectory_compressor.py`（1455 行）— 轨迹压缩
- `environments/` — RL 环境（hermes_base_env, agent_loop, tool_context, 11 个 tool_call_parsers）

依赖外部：Atropos、WandB，与 OpenCode 架构差异过大。

---

## 三、关键差异分析

### 3.1 Hermes 有但 OpenCode 缺的（移植目标）

| 组件 | 优先级 | 复杂度 | 说明 |
|------|--------|--------|------|
| **Skill CRUD** | P0 | 中 | 创建/编辑/删除技能文件 |
| **Nudge 机制** | P0 | 中高 | 自动触发后台 memory/skill 审查 |
| **Skill 安全扫描** | P0 | 中 | 60+ 威胁模式检测 |
| **增强 Compaction** | P1 | 低 | 5 阶段压缩算法 |
| **Skill Hub 市场** | P2 | 高 | 多源技能发现和安装 |

### 3.2 OpenCode 已有且可复用的

| 模块 | 状态 | 复用方式 |
|------|------|----------|
| **Memory 系统** | 已有，比 Hermes 更成熟 | 直接调用 `Memory.save()`/`Memory.search()` |
| **Skill 发现** | 已有基础 | 扩展 `Skill.Interface` 添加 CRUD |
| **Compaction** | 已有基础 | 增强 prune + summary 逻辑 |
| **Tool 注册** | 完善的 Effect Service | `Tool.define()` + `ToolRegistry.register()` |
| **Plugin 系统** | 8+ hook triggers | 可用于注入 nudge 逻辑 |
| **Bus 事件** | Effect PubSub | 发布 evolution 相关事件 |
| **Permission 系统** | 6 层评估 | Skill CRUD 工具需经过权限审批 |
| **Agent 系统** | 多 agent 定义 | 可添加 `reviewer` agent |

### 3.3 架构适配挑战

| Hermes 模式 | OpenCode 对应方案 | 难度 |
|-------------|-------------------|------|
| 守护线程 (daemon thread) | Effect Fiber / 异步 session | 中 |
| 单 AIAgent 类集中控制 | 多个 Effect Service 分散 | 低 |
| 直接文件 I/O | `Tool.Context` + `Permission` 管控 | 低 |
| Python 正则安全扫描 | TypeScript 正则（语法不同但逻辑同构） | 低 |
| 回调 + 线程 | Effect PubSub (`Bus`) | 低 |

---

## 四、移植方案（分 4 个 Phase）

### Phase 1: Skill CRUD — 让 OpenCode 可以创建/编辑/删除技能

**风险**: 低（新增模块，不修改现有代码核心逻辑）  
**工作量**: ~2-3 天

#### 涉及文件

| 操作 | 文件 | 说明 |
|------|------|------|
| 新增 | `src/skill/manager.ts` | Skill CRUD 核心逻辑（create/edit/patch/delete） |
| 新增 | `src/skill/guard.ts` | 技能安全扫描（从 Hermes 移植核心模式） |
| 新增 | `src/tool/skill-manage.ts` | `skill_manage` 工具定义 |
| 修改 | `src/tool/registry.ts` | 注册 `SkillManageTool`（1 行添加） |
| 修改 | `src/skill/index.ts` | 添加 `create/update/remove` 方法到 `Interface` |
| 修改 | `src/config/config.ts` | 添加 `experimental.skill_management` 开关 |

#### 设计要点

1. **`Skill.Interface` 扩展**:
   ```typescript
   export interface Interface {
     // 现有
     readonly get: (name: string) => Effect.Effect<Info | undefined>
     readonly all: () => Effect.Effect<Info[]>
     readonly dirs: () => Effect.Effect<string[]>
     readonly available: (agent?: Agent.Info) => Effect.Effect<Info[]>
     // 新增
     readonly create: (input: CreateInput) => Effect.Effect<Info>
     readonly update: (name: string, input: UpdateInput) => Effect.Effect<Info>
     readonly remove: (name: string) => Effect.Effect<boolean>
   }
   ```

2. **原子写入**: `Effect.fn` 实现 write-temp → rename 模式（防止写入中断导致文件损坏）

3. **安全扫描** (`guard.ts`): 移植 Hermes 的核心模式：
   - 注入检测: `system.*prompt.*override`, `ignore.*previous.*instructions`
   - 权限提升: `permission.*allow`, `auth.*disable`
   - 数据外泄: `process\.env`, `API_KEY`, `secret`
   - 代码执行: `eval\(`, `exec\(`, `subprocess`
   - 文件系统攻击: `\.\./`, `\.\.\\`

4. **`skill_manage` 工具参数**:
   ```typescript
   z.object({
     action: z.enum(["create", "edit", "patch", "delete"]),
     name: z.string(),
     description: z.string().optional(),
     content: z.string().optional(),
     category: z.string().optional(),
     tags: z.array(z.string()).optional(),
   })
   ```

5. **默认写入路径**: `.opencode/skills/<name>/SKILL.md`（遵循现有目录约定）

---

### Phase 2: Nudge 机制 — 自动触发后台 memory/skill 审查

**风险**: 中（涉及 session loop 集成）  
**工作量**: ~3-4 天

#### 涉及文件

| 操作 | 文件 | 说明 |
|------|------|------|
| 新增 | `src/evolution/nudge.ts` | Nudge Service — 计数器 + 阈值逻辑 + 后台审查触发 |
| 新增 | `src/evolution/review.ts` | 后台审查执行器（创建子 session 执行审查） |
| 新增 | `src/evolution/prompts.ts` | Memory/Skill/Combined 审查提示词 |
| 新增 | `src/evolution/index.ts` | 模块入口/导出 |
| 修改 | `src/session/prompt.ts` | 在 runLoop 结束时调用 nudge 检查（~5 行） |
| 修改 | `src/config/config.ts` | 添加 `evolution` 配置段 |
| 修改 | `src/bus/bus-event.ts` | 添加 evolution 事件定义 |

#### Nudge Service 设计

```typescript
// evolution/nudge.ts
export namespace Nudge {
  export interface Config {
    skill_interval: number    // 默认 10
    memory_interval: number   // 默认 10
    enabled: boolean          // 默认 false（opt-in）
  }

  // 状态：按 sessionID 维护计数器
  type SessionCounters = {
    turnsSinceMemory: number
    itersSinceSkill: number
  }

  export interface Interface {
    readonly tick: (sessionID: string, type: "turn" | "iteration") => Effect.Effect<void>
    readonly reset: (sessionID: string, type: "memory" | "skill") => Effect.Effect<void>
    readonly check: (sessionID: string) => Effect.Effect<{
      reviewMemory: boolean
      reviewSkill: boolean
    }>
  }
}
```

#### 后台审查实现（关键适配点）

Hermes 用守护线程 fork 一个 AIAgent → OpenCode 方案：

1. 创建一个内部 session（类似 Task subagent 模式）
2. 使用轻量模式（限制工具仅 `memory_store`/`memory_search`/`skill_manage`）
3. 注入对话历史快照 + 审查提示词
4. 异步执行，不阻塞主 session（Effect `Fiber.fork`）
5. `nudge_interval=0` 防止递归
6. 完成后通过 Bus 发布 `evolution.reviewed` 事件

```typescript
// evolution/review.ts
export namespace Review {
  export interface Interface {
    readonly execute: (input: {
      sessionID: string
      messages: MessageV2.WithParts[]
      reviewMemory: boolean
      reviewSkill: boolean
    }) => Effect.Effect<void>
  }
}
```

#### 与 session loop 的集成点

```typescript
// session/prompt.ts — 在 runLoop 的 "continue" 分支末尾
const nudgeResult = yield* nudge.check(input.sessionID)
if (nudgeResult.reviewMemory || nudgeResult.reviewSkill) {
  // 非阻塞后台审查 — Effect Fiber
  yield* Effect.fork(
    review.execute({
      sessionID: input.sessionID,
      messages: msgs,
      reviewMemory: nudgeResult.reviewMemory,
      reviewSkill: nudgeResult.reviewSkill,
    })
  )
}
```

#### 配置段设计

```jsonc
{
  "evolution": {
    "enabled": true,
    "skill_interval": 10,
    "memory_interval": 10,
    "review_max_iterations": 8,
    "review_model": "anthropic/claude-haiku"  // 用便宜模型做审查
  }
}
```

---

### Phase 3: 增强 Compaction — 移植 5 阶段压缩

**风险**: 低（增强现有模块，向后兼容）  
**工作量**: ~1-2 天

#### 涉及文件

| 操作 | 文件 | 说明 |
|------|------|------|
| 修改 | `src/session/compaction.ts` | 增强 prune 逻辑 |
| 新增 | `src/session/compaction-stages.ts` | 5 阶段压缩算法的独立实现 |
| 修改 | `src/config/config.ts` | 添加 `compaction.strategy` 开关 |

#### 设计要点

- 默认 `"basic"` 保持现有行为
- `"advanced"` 启用 5 阶段：
  1. Prune old tool results（现有 prune 增强版本）
  2. Detect head/tail boundaries（系统提示 + 最近对话为 tail）
  3. Generate structured LLM summary（限制 12K token，摘要比例 20%）
  4. Assemble messages（头部 + 摘要 + 尾部）
  5. Fix tool pairs（确保 tool_call 和 tool response 配对）

现有 `formatCompactSummary()` 已部分实现了 analysis/summary 分离，可直接扩展。

---

### Phase 4: Skill Hub（可选，建议后期）

**风险**: 中高（涉及网络请求 + 安全审查 + UI）  
**工作量**: ~5-7 天

#### 涉及文件

| 操作 | 文件 | 说明 |
|------|------|------|
| 新增 | `src/skill/hub.ts` | 多源技能市场适配器 |
| 新增 | `src/skill/hub-adapters/` | GitHub/URL/本地目录适配器 |
| 新增 | `src/tool/skill-hub.ts` | `skill_hub` 工具（browse/install/search） |
| 修改 | `src/tool/registry.ts` | 注册新工具 |

建议在 Phase 1-2 验证稳定后再实施。

---

## 五、不建议移植的部分

| 组件 | 原因 |
|------|------|
| **RL 训练管线** | 依赖 Atropos/WandB 等外部服务，架构差异过大，且 OpenCode 定位不同 |
| **批量轨迹生成** | 仅用于 RL 训练数据准备，与核心用户功能无关 |
| **轨迹压缩器** | 仅用于 RL 训练数据处理 |
| **自优化提示词** | OpenCode 已有 `base.txt` + provider-specific 提示词体系，两套系统冲突 |

---

## 六、实施路线图

```
Phase 1 (Skill CRUD)        ████████░░░░  ~2-3天
Phase 2 (Nudge + 后台审查)   ████████████  ~3-4天
Phase 3 (增强 Compaction)    ████░░░░░░░░  ~1-2天
Phase 4 (Skill Hub)          ░░░░░░░░░░░░  后期可选
```

**总估计新增代码**: ~2000-3000 行 TypeScript  
**修改现有文件**: 5-7 个文件，每个修改 5-20 行

---

## 七、安全保障措施

1. 所有新模块通过 `experimental.*` 配置开关控制，默认 `false`
2. Skill CRUD 写操作经过 Permission 系统审批
3. Skill 安全扫描在写入前执行（fail-closed）
4. Nudge 后台审查：
   - 递归保护（审查 agent 的 nudge_interval=0）
   - 工具限制（仅允许 memory + skill 相关工具）
   - max_iterations 限制（防止无限循环）
5. 不修改现有 `Skill.layer` 初始化逻辑，只扩展 Interface

---

## 八、对现有模块的影响评估

| 现有模块 | 影响 | 详情 |
|---------|------|------|
| `skill/index.ts` | 低 | 扩展 Interface，添加 3 个新方法 |
| `session/prompt.ts` | 低 | 在 loop 末尾添加 nudge check（~5 行） |
| `tool/registry.ts` | 极低 | 添加 1-2 个工具注册 |
| `config/config.ts` | 低 | 添加 `evolution` 配置段 |
| `bus/bus-event.ts` | 极低 | 添加事件类型定义 |
| `memory/` | **零** | 完全复用现有 API |
| `permission/` | **零** | 完全复用现有流程 |
| `agent/agent.ts` | 极低 | 可能添加 `reviewer` agent 定义 |
| `session/compaction.ts` | 低 | Phase 3 时增强，向后兼容 |

---

## 九、Hermes 源码关键文件索引

| 文件 | 行数 | 核心功能 |
|------|------|----------|
| `run_agent.py` | 10000+ | Nudge 计数器（1112-1212）、递增（7481-7488, 7719-7723）、阈值检查（9952-9958）、后台审查触发（9970-9980）、审查执行器（1954-2053） |
| `tools/skill_manager_tool.py` | 762 | Skill CRUD（create/edit/patch/delete + 原子写入 + 安全扫描） |
| `tools/skills_guard.py` | 977 | 安全扫描器（60+ 威胁模式） |
| `tools/skills_hub.py` | 2775 | 多源技能市场（7 个适配器） |
| `tools/skills_tool.py` | 1377 | 渐进式技能浏览（categories → list → view） |
| `tools/skills_sync.py` | 295 | 内置技能同步 |
| `agent/prompt_builder.py` | 988 | 技能索引注入（build_skills_system_prompt） |
| `agent/memory_manager.py` | 362 | Memory 编排（prefetch/sync/shutdown） |
| `agent/memory_provider.py` | 231 | Memory 抽象基类 |
| `agent/context_compressor.py` | 766 | 5 阶段压缩算法 |
| `agent/skill_commands.py` | 368 | Slash 命令扫描 |
| `agent/skill_utils.py` | 443 | Frontmatter 解析、平台过滤 |

---

**最后更新**: 2026-04-11  
**版本**: 1.0
