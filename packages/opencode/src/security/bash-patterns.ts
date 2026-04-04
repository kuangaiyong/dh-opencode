/**
 * Bash Dangerous Patterns
 *
 * Lists of dangerous command prefixes / interpreter names used by
 * the permission system to detect overly broad allow rules.
 *
 * Ported from Claude Code `utils/permissions/dangerousPatterns.ts`.
 */

/**
 * Cross-platform code-execution entry points present on both Unix and Windows.
 */
export const CROSS_PLATFORM_CODE_EXEC = [
    // Interpreters
    "python",
    "python3",
    "python2",
    "node",
    "deno",
    "tsx",
    "ruby",
    "perl",
    "php",
    "lua",
    // Package runners
    "npx",
    "bunx",
    "npm run",
    "yarn run",
    "pnpm run",
    "bun run",
    // Shells reachable from both (Git Bash / WSL on Windows, native on Unix)
    "bash",
    "sh",
    // Remote arbitrary-command wrapper
    "ssh",
] as const

/**
 * Dangerous bash command patterns — any allow rule matching one of these
 * prefixes effectively grants arbitrary code execution.
 */
export const DANGEROUS_BASH_PATTERNS: readonly string[] = [
    ...CROSS_PLATFORM_CODE_EXEC,
    "zsh",
    "fish",
    "eval",
    "exec",
    "env",
    "xargs",
    "sudo",
]

/**
 * Dangerous PowerShell command patterns.
 */
export const DANGEROUS_POWERSHELL_PATTERNS: readonly string[] = [
    ...CROSS_PLATFORM_CODE_EXEC,
    "powershell",
    "pwsh",
    "cmd",
    "cmd.exe",
    "Invoke-Expression",
    "iex",
    "Start-Process",
]

/**
 * Command substitution patterns that indicate potentially unsafe shell constructs.
 * These patterns are checked against unquoted content (single-quote-stripped).
 */
export const COMMAND_SUBSTITUTION_PATTERNS: Array<{
    pattern: RegExp
    message: string
}> = [
    { pattern: /<\(/, message: "process substitution <()" },
    { pattern: />\(/, message: "process substitution >()" },
    { pattern: /=\(/, message: "Zsh process substitution =()" },
    {
        pattern: /(?:^|[\s;&|])=[a-zA-Z_]/,
        message: "Zsh equals expansion (=cmd)",
    },
    { pattern: /\$\(/, message: "$() command substitution" },
    { pattern: /\$\{/, message: "${} parameter substitution" },
    { pattern: /\$\[/, message: "$[] legacy arithmetic expansion" },
    { pattern: /~\[/, message: "Zsh-style parameter expansion" },
    { pattern: /\(e:/, message: "Zsh-style glob qualifiers" },
    { pattern: /\(\+/, message: "Zsh glob qualifier with command execution" },
    {
        pattern: /\}\s*always\s*\{/,
        message: "Zsh always block (try/always construct)",
    },
    { pattern: /<#/, message: "PowerShell comment syntax" },
]

/**
 * Zsh-specific dangerous commands that can bypass security checks.
 * Checked against the base command (first word) of each command segment.
 */
export const ZSH_DANGEROUS_COMMANDS = new Set([
    "zmodload",
    "emulate",
    "sysopen",
    "sysread",
    "syswrite",
    "sysseek",
    "zpty",
    "ztcp",
    "zsocket",
    "mapfile",
    "zf_rm",
    "zf_mv",
    "zf_ln",
    "zf_chmod",
    "zf_chown",
    "zf_mkdir",
    "zf_rmdir",
    "zf_chgrp",
])

/**
 * Unicode whitespace characters that shell-quote treats as word separators
 * but bash treats as literal word content.
 */
// eslint-disable-next-line no-misleading-character-class
export const UNICODE_WS_RE =
    /[\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF]/

/**
 * Non-printable control characters that have no legitimate use in shell commands.
 * Excludes tab (0x09), newline (0x0A), and carriage return (0x0D) which are
 * handled by other validators.
 */
// eslint-disable-next-line no-control-regex
export const CONTROL_CHAR_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/
