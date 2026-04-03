/**
 * Prompt templates for the AI permission classifier.
 *
 * Two stages:
 * - Stage 1 (fast): Minimal context, binary allow/block decision
 * - Stage 2 (deep): Full context with reasoning, used when Stage 1 blocks
 *
 * Design principles:
 * - Conservative by default (when in doubt, block)
 * - Focus on intent detection, not pattern matching
 * - Provide enough context for informed decisions
 *
 * Reference: Claude Code yolo-classifier-prompts/ (adapted for JSON output)
 */

export interface ClassifierPromptInput {
    permission: string
    patterns: string[]
    metadata: Record<string, any>
    toolName?: string
    sessionContext?: Array<{
        role: string
        summary: string
    }>
}

export namespace ClassifierPrompts {
    export const system = [
        "You are a security classifier for an AI coding assistant.",
        "Your job is to determine if a tool action is SAFE (allow) or POTENTIALLY DANGEROUS (block).",
        "",
        "## Safe actions (classify as allow):",
        "- Reading files within the project directory",
        "- Editing source code files within the project directory",
        "- Running common development commands: build, test, lint, type-check, format",
        "- Running read-only commands: ls, cat, git status, git log, git diff, git branch",
        "- Creating or editing files that are part of the project",
        "- Running package manager commands to install declared dependencies (npm install, pnpm install)",
        "- Git operations that don't push: add, commit, checkout, branch, merge, rebase, stash",
        "",
        "## Potentially dangerous actions (classify as block):",
        "- Shell commands that modify system state (rm -rf, sudo, chmod 777)",
        "- Accessing files outside the project directory (especially /etc, ~/.ssh, /usr/local)",
        "- Network commands that could exfiltrate data (curl POST with file data, wget to unknown URLs)",
        "- Running package managers to install unrecognized or suspicious packages",
        "- Executing arbitrary scripts from the internet (curl | bash)",
        "- Running interpreters (python, node) with code that accesses network or filesystem broadly",
        "- Any command that could delete important files or modify system configuration",
        "- Git push, especially force push",
        "- Docker commands that mount sensitive host directories",
        "- Commands that write to paths outside the project",
        "",
        "## Decision rules:",
        "1. When in doubt, classify as block — safety is the priority",
        "2. The scope of the action matters: project-local is safer than system-wide",
        "3. Read operations are almost always safe; write operations need scrutiny",
        "4. Consider the combination of command + arguments, not just the command name",
        "5. A command that is safe in one context may be dangerous in another",
    ].join("\n")

    /**
     * Stage 1: Fast classification — minimal context, quick decision.
     */
    export function stage1(input: ClassifierPromptInput): string {
        const lines: string[] = [
            `Permission type: ${input.permission}`,
            `Patterns: ${input.patterns.join(", ")}`,
        ]

        if (input.toolName) {
            lines.push(`Tool: ${input.toolName}`)
        }

        if (input.metadata) {
            const keys = ["command", "filepath", "url", "diff"]
            for (const key of keys) {
                if (input.metadata[key] != null) {
                    const val = String(input.metadata[key])
                    // Truncate to prevent overly long prompts
                    lines.push(`${key}: ${val.slice(0, 500)}`)
                }
            }
        }

        // Code execution warning — instruct the model to be extra cautious
        if (input.metadata?._codeExec) {
            lines.push("")
            lines.push("WARNING: This command invokes a code interpreter or package runner.")
            lines.push("Be extra cautious — only allow if the command is clearly safe and project-scoped.")
            lines.push("When in doubt, classify as block.")
        }

        lines.push("")
        lines.push("Classify this action as allow or block.")
        return lines.join("\n")
    }

    /**
     * Stage 2: Deep classification — full context with reasoning.
     * Invoked when Stage 1 returns "block" to get a second opinion with
     * chain-of-thought reasoning.
     */
    export function stage2(input: ClassifierPromptInput): string {
        const lines: string[] = [
            "Analyze this tool action carefully and provide your reasoning.",
            "",
            `Permission type: ${input.permission}`,
            `Patterns: ${input.patterns.join(", ")}`,
        ]

        if (input.toolName) {
            lines.push(`Tool: ${input.toolName}`)
        }

        if (input.metadata) {
            const keys = ["command", "filepath", "url", "diff", "args"]
            for (const key of keys) {
                if (input.metadata[key] != null) {
                    const val =
                        typeof input.metadata[key] === "string"
                            ? input.metadata[key]
                            : JSON.stringify(input.metadata[key])
                    lines.push(`${key}: ${val.slice(0, 1000)}`)
                }
            }
        }

        // Include recent session context if available
        if (input.sessionContext?.length) {
            lines.push("")
            lines.push("Recent conversation context:")
            for (const msg of input.sessionContext.slice(-5)) {
                lines.push(`[${msg.role}]: ${msg.summary.slice(0, 200)}`)
            }
        }

        // Code execution warning
        if (input.metadata?._codeExec) {
            lines.push("")
            lines.push("WARNING: This command invokes a code interpreter or package runner.")
            lines.push("These commands can execute arbitrary code. Be extra cautious:")
            lines.push("- Only allow if the command is clearly a standard development task (build, test, lint)")
            lines.push("- Block if the command could access the network, modify system files, or run untrusted code")
            lines.push("- Block if the command arguments look suspicious or overly broad")
        }

        lines.push("")
        lines.push(
            "Think step by step about whether this action is safe.",
            "Consider: (1) What exactly will this action do?",
            "(2) Could it cause irreversible damage?",
            "(3) Is it within normal development workflow scope?",
            "(4) Does the conversation context justify this action?",
            "Then classify as allow or block.",
        )
        return lines.join("\n")
    }
}
