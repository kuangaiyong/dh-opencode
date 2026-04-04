/**
 * Bash Command Security Validation Engine
 *
 * Validates bash commands for injection attacks, dangerous patterns, and
 * parser-differential exploits before execution.
 *
 * Ported from Claude Code `tools/BashTool/bashSecurity.ts` (2592 lines).
 * This is a simplified but comprehensive version covering P0+P1 validators.
 *
 * Design principles:
 * - Pure functions, no Effect dependency
 * - No external dependencies (no tree-sitter, no shell-quote)
 * - Fail-open: returns "pass" on error (caller escalates to user)
 * - Each validator returns "pass" | "block" with a reason string
 *
 * Validators ported (P0 — must have):
 *   1. Control characters
 *   2. Command substitution ($(), ``, ${}, process substitution)
 *   3. Dangerous patterns (redirections in unquoted context)
 *   4. Newlines (multi-command hiding)
 *   5. Carriage return (parser differential)
 *   6. Unicode whitespace
 *
 * Validators ported (P1 — should have):
 *   7. IFS injection
 *   8. Brace expansion
 *   9. Zsh dangerous commands
 *  10. Obfuscated flags (ANSI-C quoting, empty quote pairs)
 *  11. Shell metacharacters in arguments
 *  12. Dangerous variables in redirection/pipe context
 */

import {
    COMMAND_SUBSTITUTION_PATTERNS,
    CONTROL_CHAR_RE,
    UNICODE_WS_RE,
    ZSH_DANGEROUS_COMMANDS,
} from "./bash-patterns"

// ─── Types ──────────────────────────────────────────────────────────────────

export type BashSecurityResult =
    | { safe: true }
    | { safe: false; message: string; isMisparsing: boolean }

// Internal validation context, built once from the command string
interface ValidationContext {
    /** The original command string as received */
    originalCommand: string
    /** First word of the command (base command name) */
    baseCommand: string
    /** Command with single-quoted content removed (preserves double-quoted) */
    unquotedContent: string
    /** Command with ALL quoted content removed */
    fullyUnquotedContent: string
    /** fullyUnquoted BEFORE stripping safe redirections (>/dev/null, 2>&1) */
    fullyUnquotedPreStrip: string
    /** Like fullyUnquotedPreStrip but preserves quote characters ('/") */
    unquotedKeepQuoteChars: string
}

// ─── Quote / content extraction ─────────────────────────────────────────────

interface QuoteExtraction {
    withDoubleQuotes: string
    fullyUnquoted: string
    unquotedKeepQuoteChars: string
}

/**
 * Extract content outside of quoted regions.
 * - `withDoubleQuotes`: removes single-quoted content but keeps double-quoted
 * - `fullyUnquoted`: removes both single- and double-quoted content
 * - `unquotedKeepQuoteChars`: like fullyUnquoted but keeps the quote delimiters
 */
function extractQuotedContent(command: string): QuoteExtraction {
    let withDoubleQuotes = ""
    let fullyUnquoted = ""
    let unquotedKeepQuoteChars = ""
    let inSingleQuote = false
    let inDoubleQuote = false
    let escaped = false

    for (let i = 0; i < command.length; i++) {
        const char = command[i]!

        if (escaped) {
            escaped = false
            if (!inSingleQuote) withDoubleQuotes += char
            if (!inSingleQuote && !inDoubleQuote) fullyUnquoted += char
            if (!inSingleQuote && !inDoubleQuote) unquotedKeepQuoteChars += char
            continue
        }

        if (char === "\\" && !inSingleQuote) {
            escaped = true
            if (!inSingleQuote) withDoubleQuotes += char
            if (!inSingleQuote && !inDoubleQuote) fullyUnquoted += char
            if (!inSingleQuote && !inDoubleQuote) unquotedKeepQuoteChars += char
            continue
        }

        if (char === "'" && !inDoubleQuote) {
            inSingleQuote = !inSingleQuote
            unquotedKeepQuoteChars += char
            continue
        }

        if (char === '"' && !inSingleQuote) {
            inDoubleQuote = !inDoubleQuote
            unquotedKeepQuoteChars += char
            continue
        }

        if (!inSingleQuote) withDoubleQuotes += char
        if (!inSingleQuote && !inDoubleQuote) fullyUnquoted += char
        if (!inSingleQuote && !inDoubleQuote) unquotedKeepQuoteChars += char
    }

    return { withDoubleQuotes, fullyUnquoted, unquotedKeepQuoteChars }
}

/**
 * Strip safe redirections that don't write to user-controlled paths.
 * SECURITY: All patterns MUST have a trailing boundary (?=\s|$).
 */
function stripSafeRedirections(content: string): string {
    return content
        .replace(/\s+2\s*>&\s*1(?=\s|$)/g, "")
        .replace(/[012]?\s*>\s*\/dev\/null(?=\s|$)/g, "")
        .replace(/\s*<\s*\/dev\/null(?=\s|$)/g, "")
}

/**
 * Check if content contains an unescaped occurrence of a single character.
 */
function hasUnescapedChar(content: string, char: string): boolean {
    let escaped = false
    for (let i = 0; i < content.length; i++) {
        const c = content[i]
        if (escaped) {
            escaped = false
            continue
        }
        if (c === "\\") {
            escaped = true
            continue
        }
        if (c === char) return true
    }
    return false
}

/**
 * Build the validation context from a raw command string.
 */
function buildContext(command: string): ValidationContext {
    const baseCommand = command.split(" ")[0] || ""
    const { withDoubleQuotes, fullyUnquoted, unquotedKeepQuoteChars } =
        extractQuotedContent(command)

    return {
        originalCommand: command,
        baseCommand,
        unquotedContent: withDoubleQuotes,
        fullyUnquotedContent: stripSafeRedirections(fullyUnquoted),
        fullyUnquotedPreStrip: fullyUnquoted,
        unquotedKeepQuoteChars,
    }
}

// ─── Validators ─────────────────────────────────────────────────────────────
// Each returns null (pass) or a BashSecurityResult with safe=false.

type ValidatorFn = (ctx: ValidationContext) => BashSecurityResult | null

// --- P0: Control characters ---

function validateControlCharacters(ctx: ValidationContext): BashSecurityResult | null {
    if (CONTROL_CHAR_RE.test(ctx.originalCommand)) {
        return {
            safe: false,
            message: "Command contains non-printable control characters that could bypass security checks",
            isMisparsing: true,
        }
    }
    return null
}

// --- P0: Command substitution & dangerous patterns ---

function validateDangerousPatterns(ctx: ValidationContext): BashSecurityResult | null {
    const { unquotedContent } = ctx

    // Unescaped backticks
    if (hasUnescapedChar(unquotedContent, "`")) {
        return {
            safe: false,
            message: "Command contains backticks (`) for command substitution",
            isMisparsing: true,
        }
    }

    // Other command substitution patterns
    for (const { pattern, message } of COMMAND_SUBSTITUTION_PATTERNS) {
        if (pattern.test(unquotedContent)) {
            return {
                safe: false,
                message: `Command contains ${message}`,
                isMisparsing: true,
            }
        }
    }

    return null
}

// --- P0: Redirections ---

function validateRedirections(ctx: ValidationContext): BashSecurityResult | null {
    const { fullyUnquotedContent } = ctx

    if (/</.test(fullyUnquotedContent)) {
        return {
            safe: false,
            message: "Command contains input redirection (<) which could read sensitive files",
            isMisparsing: false,
        }
    }

    if (/>/.test(fullyUnquotedContent)) {
        return {
            safe: false,
            message: "Command contains output redirection (>) which could write to arbitrary files",
            isMisparsing: false,
        }
    }

    return null
}

// --- P0: Newlines ---

function validateNewlines(ctx: ValidationContext): BashSecurityResult | null {
    const { fullyUnquotedPreStrip } = ctx

    if (!/[\n\r]/.test(fullyUnquotedPreStrip)) return null

    // Flag newline/CR followed by non-whitespace, EXCEPT safe backslash-newline continuations
    // at word boundaries. Mid-word continuations like `tr\<newline>aceroute` are flagged.
    const looksLikeCommand = /(?<![\s]\\)[\n\r]\s*\S/.test(fullyUnquotedPreStrip)
    if (looksLikeCommand) {
        return {
            safe: false,
            message: "Command contains newlines that could separate multiple commands",
            isMisparsing: false,
        }
    }

    return null
}

// --- P0: Carriage return (parser differential) ---

function validateCarriageReturn(ctx: ValidationContext): BashSecurityResult | null {
    const { originalCommand } = ctx

    if (!originalCommand.includes("\r")) return null

    // CR outside double quotes causes shell-quote/bash tokenization differential
    let inSingleQuote = false
    let inDoubleQuote = false
    let escaped = false

    for (let i = 0; i < originalCommand.length; i++) {
        const c = originalCommand[i]
        if (escaped) {
            escaped = false
            continue
        }
        if (c === "\\" && !inSingleQuote) {
            escaped = true
            continue
        }
        if (c === "'" && !inDoubleQuote) {
            inSingleQuote = !inSingleQuote
            continue
        }
        if (c === '"' && !inSingleQuote) {
            inDoubleQuote = !inDoubleQuote
            continue
        }
        if (c === "\r" && !inDoubleQuote) {
            return {
                safe: false,
                message:
                    "Command contains carriage return (\\r) which shell-quote and bash tokenize differently",
                isMisparsing: true,
            }
        }
    }

    return null
}

// --- P0: Unicode whitespace ---

function validateUnicodeWhitespace(ctx: ValidationContext): BashSecurityResult | null {
    if (UNICODE_WS_RE.test(ctx.originalCommand)) {
        return {
            safe: false,
            message: "Command contains Unicode whitespace characters that could cause parsing inconsistencies",
            isMisparsing: true,
        }
    }
    return null
}

// --- P1: IFS injection ---

function validateIFSInjection(ctx: ValidationContext): BashSecurityResult | null {
    if (/\$IFS|\$\{[^}]*IFS/.test(ctx.originalCommand)) {
        return {
            safe: false,
            message: "Command contains IFS variable usage which could bypass security validation",
            isMisparsing: true,
        }
    }
    return null
}

// --- P1: Brace expansion ---

function validateBraceExpansion(ctx: ValidationContext): BashSecurityResult | null {
    const { fullyUnquotedPreStrip } = ctx

    // Look for {a,b} or {1..5} patterns outside quotes
    if (/\{[^}]*[,.]\.?[^}]*\}/.test(fullyUnquotedPreStrip)) {
        return {
            safe: false,
            message: "Command contains brace expansion that could generate unexpected arguments",
            isMisparsing: true,
        }
    }
    return null
}

// --- P1: Zsh dangerous commands ---

function validateZshDangerousCommands(ctx: ValidationContext): BashSecurityResult | null {
    const { baseCommand } = ctx

    if (ZSH_DANGEROUS_COMMANDS.has(baseCommand)) {
        return {
            safe: false,
            message: `Command uses Zsh-specific dangerous command: ${baseCommand}`,
            isMisparsing: true,
        }
    }

    // Also check for `fc -e` which can execute arbitrary commands
    if (baseCommand === "fc" && /\bfc\s+.*-e/.test(ctx.originalCommand)) {
        return {
            safe: false,
            message: "Command uses 'fc -e' which can execute arbitrary commands via editor",
            isMisparsing: true,
        }
    }

    return null
}

// --- P1: Obfuscated flags ---

function validateObfuscatedFlags(ctx: ValidationContext): BashSecurityResult | null {
    const { originalCommand } = ctx

    // ANSI-C quoting in flags: $'\x2d' is '-', $'\x65' is 'e', etc.
    if (/\$'[^']*\\x[0-9a-fA-F]{2}[^']*'/.test(originalCommand)) {
        return {
            safe: false,
            message: "Command contains ANSI-C quoted hex escape that could obfuscate flags",
            isMisparsing: true,
        }
    }

    // Locale quoting ($"...") — can translate strings, confusing static checks
    if (/\$"/.test(originalCommand)) {
        return {
            safe: false,
            message: "Command contains locale-dependent quoting ($\"...\") that could obfuscate content",
            isMisparsing: true,
        }
    }

    // Empty quote pairs used to break up flag recognition: -""e or ''--exec
    if (/(?:''|""){2,}/.test(originalCommand) || /--?(?:''|"")\w/.test(originalCommand)) {
        return {
            safe: false,
            message: "Command contains empty quote pairs that could obfuscate flags",
            isMisparsing: true,
        }
    }

    return null
}

// --- P1: Shell metacharacters ---

function validateShellMetacharacters(ctx: ValidationContext): BashSecurityResult | null {
    const { fullyUnquotedContent } = ctx

    // Unquoted semicolons, pipes, and background operators in argument positions
    // (not command separators which are handled by the command parser)
    // We check for these after the first word (base command)
    const afterBaseCmd = fullyUnquotedContent.slice(ctx.baseCommand.length)
    if (/[;|&]/.test(afterBaseCmd)) {
        // This is a simplified check — Claude Code's version is more nuanced
        // with find/grep pattern detection. For safety, we flag all unquoted
        // metacharacters in the argument portion.
        return {
            safe: false,
            message: "Command contains unquoted shell metacharacters (;, |, &) in arguments",
            isMisparsing: false,
        }
    }

    return null
}

// --- P1: Dangerous variables in redirection/pipe context ---

function validateDangerousVariables(ctx: ValidationContext): BashSecurityResult | null {
    const { fullyUnquotedContent } = ctx

    // Variables used in redirection targets or pipe destinations
    if (/>\s*\$\w/.test(fullyUnquotedContent) || /\$\w.*\|/.test(fullyUnquotedContent)) {
        return {
            safe: false,
            message: "Command uses variables in dangerous contexts (redirection targets or pipe sources)",
            isMisparsing: false,
        }
    }

    return null
}

// --- P1: Comment-quote desync ---

function validateCommentQuoteDesync(ctx: ValidationContext): BashSecurityResult | null {
    const { originalCommand } = ctx

    // Track quote state and detect # comments containing quote characters
    let inSingleQuote = false
    let inDoubleQuote = false
    let escaped = false

    for (let i = 0; i < originalCommand.length; i++) {
        const char = originalCommand[i]

        if (escaped) {
            escaped = false
            continue
        }

        if (inSingleQuote) {
            if (char === "'") inSingleQuote = false
            continue
        }

        if (char === "\\") {
            escaped = true
            continue
        }

        if (char === '"') {
            inDoubleQuote = !inDoubleQuote
            continue
        }

        if (char === "'" && !inDoubleQuote) {
            inSingleQuote = true
            continue
        }

        // Unquoted # — check rest of line for quote chars
        if (char === "#" && !inDoubleQuote && !inSingleQuote) {
            // Check if preceded by whitespace or at start (actual comment)
            if (i === 0 || /\s/.test(originalCommand[i - 1] || "")) {
                const restOfLine = originalCommand.slice(i + 1).split("\n")[0] || ""
                if (/['"]/.test(restOfLine)) {
                    return {
                        safe: false,
                        message:
                            "Command contains # comment with quote characters that could desync quote tracking",
                        isMisparsing: true,
                    }
                }
            }
        }
    }

    return null
}

// --- P1: Backslash-escaped whitespace ---

function validateBackslashEscapedWhitespace(ctx: ValidationContext): BashSecurityResult | null {
    const { fullyUnquotedPreStrip } = ctx

    // Backslash-space or backslash-tab outside quotes
    if (/\\ |\\\t/.test(fullyUnquotedPreStrip)) {
        return {
            safe: false,
            message:
                "Command contains backslash-escaped whitespace that could enable path traversal",
            isMisparsing: true,
        }
    }

    return null
}

// --- P1: Backslash-escaped operators ---

function validateBackslashEscapedOperators(ctx: ValidationContext): BashSecurityResult | null {
    const { fullyUnquotedPreStrip } = ctx

    // \; \| \& \< \> — shell treats these as literal chars, but our
    // command splitter may interpret them as operators
    if (/\\[;|&<>]/.test(fullyUnquotedPreStrip)) {
        return {
            safe: false,
            message:
                "Command contains backslash-escaped shell operators that could bypass command splitting",
            isMisparsing: true,
        }
    }

    return null
}

// --- P1: Mid-word hash ---

function validateMidWordHash(ctx: ValidationContext): BashSecurityResult | null {
    const { unquotedKeepQuoteChars } = ctx

    // # preceded by non-whitespace (mid-word): shell-quote treats it as
    // comment-start but bash treats it as literal character
    // Exclude ${# which is bash string-length syntax
    if (/\S(?<!\$\{)#/.test(unquotedKeepQuoteChars)) {
        return {
            safe: false,
            message: "Command contains mid-word # which is parsed differently by shell-quote vs bash",
            isMisparsing: true,
        }
    }

    return null
}

// --- P1: /proc/*/environ access ---

function validateProcEnvironAccess(ctx: ValidationContext): BashSecurityResult | null {
    if (/\/proc\/[^/]*\/environ/.test(ctx.originalCommand)) {
        return {
            safe: false,
            message: "Command accesses /proc/*/environ which could expose sensitive environment variables",
            isMisparsing: false,
        }
    }
    return null
}

// ─── Main Entry Point ───────────────────────────────────────────────────────

/**
 * Non-misparsing validators — their "block" results go through the standard
 * permission flow rather than being hard-blocked. These detect real concerns
 * (redirections, newlines) that aren't parser-differential exploits.
 */
const NON_MISPARSING_VALIDATORS = new Set<ValidatorFn>([
    validateNewlines,
    validateRedirections,
    validateShellMetacharacters,
    validateDangerousVariables,
    validateProcEnvironAccess,
])

/**
 * Validate a bash command for security concerns.
 *
 * Returns `{ safe: true }` if the command passes all checks.
 * Returns `{ safe: false, message, isMisparsing }` if a concern is found:
 * - `isMisparsing: true`  → hard block, parser differential exploit
 * - `isMisparsing: false` → soft block, real concern but not an exploit
 *
 * @param command  The raw bash command string to validate
 */
export function validateBashCommand(command: string): BashSecurityResult {
    // Early exit: empty commands are safe
    if (!command.trim()) {
        return { safe: true }
    }

    // Pre-check: control characters (before any parsing)
    const ctrlResult = validateControlCharacters({ originalCommand: command } as ValidationContext)
    if (ctrlResult) return ctrlResult

    // Build the validation context
    const ctx = buildContext(command)

    // Validator pipeline — order matters:
    // 1. Misparsing-critical validators first
    // 2. Non-misparsing validators last
    // 3. We defer non-misparsing results to ensure misparsing ones always take priority
    const validators: ValidatorFn[] = [
        validateObfuscatedFlags,
        validateShellMetacharacters,
        validateDangerousVariables,
        validateCommentQuoteDesync,
        validateCarriageReturn,
        validateNewlines,
        validateIFSInjection,
        validateProcEnvironAccess,
        validateDangerousPatterns,
        validateRedirections,
        validateBackslashEscapedWhitespace,
        validateBackslashEscapedOperators,
        validateUnicodeWhitespace,
        validateMidWordHash,
        validateBraceExpansion,
        validateZshDangerousCommands,
    ]

    // Defer non-misparsing ask results — continue running validators.
    // If any misparsing validator fires, return THAT. Only if we reach the
    // end without a misparsing result, return the deferred non-misparsing one.
    let deferredResult: BashSecurityResult | null = null

    for (const validator of validators) {
        const result = validator(ctx)
        if (result && !result.safe) {
            if (NON_MISPARSING_VALIDATORS.has(validator)) {
                if (!deferredResult) deferredResult = result
                continue
            }
            // Misparsing validator fired — return immediately
            return result
        }
    }

    if (deferredResult) return deferredResult

    return { safe: true }
}
