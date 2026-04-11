# Evolution-Hermes 分支核心特性及使用方式

## 一、默认启用的功能（无需配置）

| 功能 | 说明 |
|------|------|
| **基础提示词分层** | 引入 `base.txt` 统一模板，所有 provider 自动继承身份/语气/工具策略等通用指令 |
| **目录树展示** | git 项目自动在系统提示词中包含目录结构（修复了 `&& false` Bug） |
| **结构化压缩摘要** | 压缩时采用 `<analysis>` + `<summary>` 思维链格式，技术信息逐字保留 |
| **analysis 块自动清理** | 压缩后自动剥离 `<analysis>` 块，节省上下文 token |
| **o1/o3 模型路由修复** | 不再错误路由到 beast 模式 |

---

## 二、需要手动启用的功能

在 `opencode.json` 中配置：

### 1. 高级压缩策略

```jsonc
{
  "experimental": {
    "compaction_strategy": "advanced"
  }
}
```

- 激进截断旧工具输出（保留前 60% + 后 20%）
- 保护最近 6 条消息不被压缩
- 在 LLM 摘要之前先回收 token

### 2. 运行时技能管理（AI 自动创建/编辑/删除技能）

```jsonc
{
  "experimental": {
    "skill_management": true
  }
}
```

- AI 获得 `skill_manage` 工具，支持 create/edit/patch/delete/list/read/scan 7 种操作
- 技能存储路径：`<worktree>/.opencode/skills/<name>/SKILL.md`
- 内置 60+ 安全威胁模式扫描，阻断 critical/high 级别威胁

### 3. Evolution 系统（后台记忆/技能审查）

```jsonc
{
  "experimental": {
    "evolution": {
      "enabled": true,
      "memory_nudge_interval": 10,
      "skill_nudge_interval": 15
    }
  }
}
```

- 定期提醒 AI 审查并自动保存记忆/技能
- 灵感来自 Hermes Agent 的 nudge 机制

---

## 三、完整配置示例

```jsonc
{
  "experimental": {
    "skill_management": true,
    "evolution": {
      "enabled": true,
      "memory_nudge_interval": 10,
      "skill_nudge_interval": 15
    },
    "compaction_strategy": "advanced"
  }
}
```

---

## 四、功能矩阵

| 功能 | 默认启用 | 配置项 | 影响范围 |
|------|----------|--------|----------|
| 基础提示词分层（base.txt） | **是** | 无需配置 | 所有 provider |
| 目录树展示 | **是** | 无需配置（git 项目自动生效） | system prompt |
| 结构化压缩摘要（analysis + summary） | **是** | 无需配置 | compaction |
| analysis 块自动清理 | **是** | 无需配置 | compaction |
| 高级压缩策略 | 否 | `experimental.compaction_strategy: "advanced"` | compaction |
| 运行时技能管理 | 否 | `experimental.skill_management: true` | skill CRUD |
| Evolution 系统 | 否 | `experimental.evolution.enabled: true` | 后台审查 |
| o1/o3 模型改用 GPT prompt | **是** | 无需配置 | model routing |

---

## 五、架构变更详情

### 5.1 提示词分层架构

引入 `session/prompt/base.txt`（93 行）作为所有 provider 的通用基础层，形成双层结构：

```
[base.txt] + [provider-specific.txt]  →  最终系统提示词
```

Provider 映射关系：

| Provider | Prompt 组合 |
|----------|-------------|
| GPT | [base, gpt] |
| Codex | [base, codex] |
| o1/o3 | [base, gpt]（旧版用 beast） |
| Gemini | [base, gemini] |
| Claude | [base, anthropic] |
| Trinity | [base, trinity] |
| 其他 | [base, default] |

### 5.2 压缩算法改进

- **compaction.txt**：重写为禁止工具调用的结构化摘要指令
- **compaction.ts**：新增 `formatCompactSummary()` 函数，自动清理 `<analysis>` 块
- **compaction-stages.ts**（新文件）：高级压缩两阶段管道
  - Stage 1: `truncateToolOutputs()` — 激进工具输出截断
  - Stage 2: `findProtectedBoundaries()` — 受保护边界检测

### 5.3 技能管理系统

新增文件：

| 文件 | 行数 | 功能 |
|------|------|------|
| `skill/manager.ts` | 284 | 技能 CRUD 核心实现（YAML frontmatter + Markdown 格式） |
| `skill/guard.ts` | 446 | 安全扫描器（60+ 威胁模式，8 大威胁类别，4 级严重度） |
| `tool/skill-manage.ts` | 206 | `skill_manage` 工具定义（7 种操作） |

### 5.4 删除的文件

- `session/prompt/copilot-gpt-5.txt`（143 行）— 专为 Copilot GPT-5 编写的超长 prompt
- `session/prompt/plan-reminder-anthropic.txt`（67 行）— Plan Mode 系统提醒

---

**分支**: `evolution-hermes`（基于 `master`）
**变更统计**: 16 个文件（+412 行，-937 行）
**最后更新**: 2026-04-11
