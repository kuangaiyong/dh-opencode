/**
 * Safe tool allowlist and dangerous patterns for the AI permission classifier.
 *
 * Tools in the allowlist are considered safe (read-only or no side effects)
 * and will be auto-approved without invoking the LLM classifier.
 *
 * Dangerous bash patterns are hard-coded safeguards that force escalation
 * to the user regardless of classifier output.
 *
 * Reference: Claude Code classifierDecision.ts / dangerousPatterns.ts
 */

/**
 * Tools that are safe and don't need any classifier checking.
 * These are read-only or have no meaningful side effects.
 */
export const SAFE_TOOL_ALLOWLIST = new Set([
    // Read-only file operations
    "read",
    "glob",
    "grep",
    "list",

    // Search and analysis (read-only)
    "codesearch",
    "websearch",
    "webfetch",

    // Auxiliary tools (no side effects)
    "todowrite",
    "question",

    // LSP operations (read-only queries)
    "lsp",

    // Memory operations (record only)
    "memory_search",
    "memory_get",
    "memory_store",
    "memory_forget",
])

/**
 * Permission types considered high-risk — classifier should be more
 * conservative when evaluating these.
 */
export const HIGH_RISK_PERMISSIONS = new Set([
    "bash",
    "external_directory",
])

/**
 * Dangerous bash command patterns.
 * If any of these match the command string, the classifier will always
 * escalate to the user regardless of its own judgment.
 *
 * Reference: Claude Code dangerousPatterns.ts (external-user subset)
 */
export const DANGEROUS_BASH_PATTERNS: readonly RegExp[] = [
    /\brm\s+-r(?:f)?\s+[/~]/i,           // rm -rf / or ~
    /\bsudo\b/i,                           // sudo commands
    /\bchmod\s+777\b/i,                    // chmod 777
    /\b(?:curl|wget)\b.*\|\s*\b(?:bash|sh|zsh)\b/i, // curl | bash
    /\bdd\s+if=/i,                         // dd disk write
    />\s*\/dev\//i,                         // write to /dev/
    /\bmkfs\b/i,                           // format filesystem
    /\b(?:shutdown|reboot|halt|poweroff)\b/i, // shutdown/reboot
    /\bkill\s+-9\s+1\b/i,                 // kill -9 1 (init process)
    /\b(?:rm|del)\s+.*(?:\/etc\/|\\windows\\)/i, // remove system files
    // Windows-specific dangerous patterns
    /\b(?:powershell|pwsh)(?:\.exe)?\s+.*-(?:e|enc|encodedcommand)\b/i, // encoded PowerShell
    /\b(?:cmd|cmd\.exe)\s+\/c\b/i,        // cmd /c arbitrary execution
    /\breg\s+(?:add|delete|import)\b/i,    // Windows registry modification
    /\bformat\s+[a-z]:/i,                  // format drive
    /\bnet\s+user\b/i,                     // user account modification
    /\bbcdedit\b/i,                         // boot config modification
]

/**
 * Interpreter / code-execution entry points that should be classified
 * more conservatively (not auto-allowed even if command looks simple).
 *
 * Reference: Claude Code dangerousPatterns.ts CROSS_PLATFORM_CODE_EXEC
 */
export const CODE_EXEC_PREFIXES: readonly string[] = [
    // Interpreters
    "python",
    "python3",
    "node",
    "deno",
    "tsx",
    "ruby",
    "perl",
    "php",
    // Package runners
    "npx",
    "bunx",
    "npm run",
    "yarn run",
    "pnpm run",
    "bun run",
    // Shells
    "bash",
    "sh",
    "zsh",
    // Windows shells
    "powershell",
    "pwsh",
    "cmd",
    "cmd.exe",
    // Remote execution
    "ssh",
    "eval",
    "exec",
]

/**
 * Check if a command string matches any dangerous bash pattern.
 */
export function isDangerousBashCommand(command: string): boolean {
    return DANGEROUS_BASH_PATTERNS.some((pattern) => pattern.test(command))
}

/**
 * Check if a command starts with a code execution prefix.
 * These commands invoke interpreters or package runners that can execute
 * arbitrary code, and should be classified more conservatively.
 */
export function isCodeExecCommand(command: string): boolean {
    const trimmed = command.trim()
    return CODE_EXEC_PREFIXES.some(
        (prefix) => trimmed === prefix || trimmed.startsWith(prefix + " "),
    )
}
