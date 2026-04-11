import { Ripgrep } from "../file/ripgrep"

import { Instance } from "../project/instance"

import PROMPT_BASE from "./prompt/base.txt"
import PROMPT_ANTHROPIC from "./prompt/anthropic.txt"
import PROMPT_DEFAULT from "./prompt/default.txt"
import PROMPT_BEAST from "./prompt/beast.txt"
import PROMPT_GEMINI from "./prompt/gemini.txt"
import PROMPT_GPT from "./prompt/gpt.txt"

import PROMPT_CODEX from "./prompt/codex.txt"
import PROMPT_TRINITY from "./prompt/trinity.txt"
import type { Provider } from "@/provider/provider"
import type { Agent } from "@/agent/agent"
import { Permission } from "@/permission"
import { Skill } from "@/skill"

export namespace SystemPrompt {
  export function provider(model: Provider.Model) {
    if (model.api.id.includes("gpt")) {
      if (model.api.id.includes("codex")) {
        return [PROMPT_BASE, PROMPT_CODEX]
      }
      return [PROMPT_BASE, PROMPT_GPT]
    }
    if (model.api.id.includes("o1") || model.api.id.includes("o3"))
      return [PROMPT_BASE, PROMPT_GPT]
    if (model.api.id.includes("gemini-")) return [PROMPT_BASE, PROMPT_GEMINI]
    if (model.api.id.includes("claude")) return [PROMPT_BASE, PROMPT_ANTHROPIC]
    if (model.api.id.toLowerCase().includes("trinity")) return [PROMPT_BASE, PROMPT_TRINITY]
    return [PROMPT_BASE, PROMPT_DEFAULT]
  }

  export async function environment(model: Provider.Model) {
    const project = Instance.project
    return [
      [
        `You are powered by the model named ${model.api.id}. The exact model ID is ${model.providerID}/${model.api.id}`,
        `Here is some useful information about the environment you are running in:`,
        `<env>`,
        `  Working directory: ${Instance.directory}`,
        `  Workspace root folder: ${Instance.worktree}`,
        `  Is directory a git repo: ${project.vcs === "git" ? "yes" : "no"}`,
        `  Platform: ${process.platform}`,
        `  Today's date: ${new Date().toDateString()}`,
        `</env>`,
        `<directories>`,
        `  ${
          project.vcs === "git"
            ? await Ripgrep.tree({
                cwd: Instance.directory,
                limit: 50,
              })
            : ""
        }`,
        `</directories>`,
      ].join("\n"),
    ]
  }

  export async function skills(agent: Agent.Info) {
    if (Permission.disabled(["skill"], agent.permission).has("skill")) return

    const list = await Skill.available(agent)

    return [
      "Skills provide specialized instructions and workflows for specific tasks.",
      "Use the skill tool to load a skill when a task matches its description.",
      // the agents seem to ingest the information about skills a bit better if we present a more verbose
      // version of them here and a less verbose version in tool description, rather than vice versa.
      Skill.fmt(list, { verbose: true }),
    ].join("\n")
  }

  export function memory(filepath?: string) {
    const loc = filepath ? ` Its path is shown in the <permanent-memory> tag below.` : ""
    return [
      "## Memory System",
      "",
      "You wake up fresh each session with NO memory of previous conversations.",
      "The files below ARE your memory. Without them, everything is lost.",
      "",
      "### MEMORY.md — Permanent Memory (you maintain this)",
      "",
      `MEMORY.md stores durable, cross-session knowledge.${loc}`,
      "Its content is loaded into your context at session start (shown in <permanent-memory> tags).",
      "",
      "**WRITE IT DOWN — No Mental Notes!**",
      "",
      "Your memory does NOT survive session restarts. If you want to remember something, WRITE IT TO MEMORY.md IMMEDIATELY. Do not make 'mental notes'. Do not plan to 'save it later'. Write it now.",
      "",
      "**How to write to MEMORY.md:**",
      "",
      "- Use the **Edit** or **Write** tool on the MEMORY.md path shown in <permanent-memory>.",
      "- Do NOT use the memory_store tool for permanent info — that tool saves to daily memory files (memory/*.md), not MEMORY.md.",
      "- If MEMORY.md is empty, create organized sections (## User Info, ## Preferences, ## Decisions, etc.).",
      "- If MEMORY.md already has content, use Edit to append or update specific sections.",
      "",
      "**You MUST proactively update MEMORY.md when you learn ANY of the following:**",
      "",
      "- User identity: name, role, location, team, organization",
      "- User preferences: language, coding style, tool choices, communication style",
      "- Key technical decisions and their rationale",
      "- Project conventions, architecture patterns, important file paths",
      "- Recurring context that comes up across conversations",
      "- Lessons learned, mistakes to avoid, gotchas discovered",
      "- Explicit requests to remember something (\"记住\", \"remember this\")",
      "",
      "**Rules:**",
      "- When the user tells you ANYTHING about themselves, edit MEMORY.md immediately without asking permission.",
      "- When a significant decision is made, record it and the rationale.",
      "- Do not wait for the user to say \"remember\" or \"save\". Be proactive.",
      "- Keep MEMORY.md organized with clear headings and concise entries.",
      "- Remove outdated entries when you notice them.",
      "",
      "### memory/*.md — Daily Memory (system-managed)",
      "",
      "Daily memory files (memory/YYYY-MM-DD.md) are automatically generated by the system to capture session summaries and compaction context.",
      "Recent daily files are loaded into your context at session start (shown in <recent-memory> tags if present).",
      "Do NOT manually edit daily memory files — they are system-managed.",
      "",
      "### Memory Recall",
      "",
      "Before answering anything about prior work, decisions, dates, people, preferences, or todos: first check the <permanent-memory> and <recent-memory> content already in your context. If insufficient, use memory_search then memory_get. If low confidence after search, say you checked.",
      "",
      "### memory_store Tool",
      "",
      "The memory_store tool writes to daily memory files (memory/*.md). Use it only for secondary or supplemental context that doesn't belong in MEMORY.md.",
      "For permanent info (user identity, preferences, key decisions), always edit MEMORY.md directly.",
    ].join("\n")
  }
}
