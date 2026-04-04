/**
 * Dangerous Permission Rules Detection
 *
 * Detects and optionally strips permission rules that would bypass the
 * AI classifier by auto-allowing dangerous commands (interpreters,
 * code execution tools, etc.).
 *
 * Ported from Claude Code `utils/permissions/permissionSetup.ts`.
 *
 * Example dangerous rules:
 * - { permission: "bash", pattern: "*", action: "allow" }        → allows ALL commands
 * - { permission: "bash", pattern: "python:*", action: "allow" } → allows arbitrary Python
 * - { permission: "bash", pattern: "node *", action: "allow" }   → allows arbitrary Node.js
 *
 * Design:
 * - Pure functions, no Effect dependency
 * - Used at classifier call-time to filter rules, not globally
 */

import {
    DANGEROUS_BASH_PATTERNS,
    DANGEROUS_POWERSHELL_PATTERNS,
} from "@/security/bash-patterns"

// OpenCode rule type (matches Permission.Rule)
interface PermissionRule {
    permission: string
    pattern: string
    action: string
}

/**
 * Check if a bash permission rule is dangerous for auto mode.
 *
 * A rule is dangerous if it would auto-allow commands that execute arbitrary code,
 * bypassing the classifier's safety evaluation.
 *
 * Dangerous forms:
 * 1. pattern = "*"          → allows ALL commands
 * 2. pattern = "python:*"   → interpreter prefix wildcard
 * 3. pattern = "python*"    → interpreter name wildcard
 * 4. pattern = "python *"   → interpreter with args wildcard
 * 5. pattern = "python -c*" → interpreter with flag wildcard
 */
export function isDangerousBashPattern(pattern: string): boolean {
    const content = pattern.trim().toLowerCase()

    // Standalone wildcard matches everything
    if (content === "*") return true

    for (const dangerous of DANGEROUS_BASH_PATTERNS) {
        const lower = dangerous.toLowerCase()

        // Exact match
        if (content === lower) return true
        // Prefix syntax: "python:*"
        if (content === `${lower}:*`) return true
        // Wildcard at end: "python*"
        if (content === `${lower}*`) return true
        // Wildcard with space: "python *"
        if (content === `${lower} *`) return true
        // Flag wildcard: "python -c*", "python -m*"
        if (content.startsWith(`${lower} -`) && content.endsWith("*")) return true
    }

    return false
}

/**
 * Check if a PowerShell permission rule is dangerous for auto mode.
 */
export function isDangerousPowerShellPattern(pattern: string): boolean {
    const content = pattern.trim().toLowerCase()

    if (content === "*") return true

    for (const dangerous of DANGEROUS_POWERSHELL_PATTERNS) {
        const lower = dangerous.toLowerCase()

        if (content === lower) return true
        if (content === `${lower}:*`) return true
        if (content === `${lower}*`) return true
        if (content === `${lower} *`) return true
        if (content.startsWith(`${lower} -`) && content.endsWith("*")) return true

        // .exe variant: python.exe, node.exe, etc.
        const sp = lower.indexOf(" ")
        const exe = sp === -1
            ? `${lower}.exe`
            : `${lower.slice(0, sp)}.exe${lower.slice(sp)}`
        if (content === exe) return true
        if (content === `${exe}:*`) return true
        if (content === `${exe}*`) return true
        if (content === `${exe} *`) return true
        if (content.startsWith(`${exe} -`) && content.endsWith("*")) return true
    }

    return false
}

/**
 * Check if a single permission rule is dangerous for auto mode / classifier.
 *
 * Only `allow` rules for `bash` permissions are checked.
 * `deny` and `ask` rules are never dangerous (they restrict, not permit).
 */
export function isDangerousRule(rule: PermissionRule): boolean {
    if (rule.action !== "allow") return false

    if (rule.permission === "bash") {
        return isDangerousBashPattern(rule.pattern)
    }

    // PowerShell rules (if they exist in the ruleset)
    if (rule.permission === "powershell") {
        return isDangerousPowerShellPattern(rule.pattern)
    }

    return false
}

/**
 * Filter a ruleset to remove dangerous allow rules.
 *
 * Returns a new ruleset with dangerous rules removed. This is used at
 * classifier call-time so the classifier's safety evaluation is not
 * bypassed by overly broad user-configured rules.
 *
 * @param ruleset   The original ruleset
 * @returns         Filtered ruleset (same reference if no changes)
 */
export function stripDangerousRules(ruleset: PermissionRule[]): PermissionRule[] {
    const filtered = ruleset.filter((rule) => !isDangerousRule(rule))
    return filtered.length === ruleset.length ? ruleset : filtered
}

/**
 * Find all dangerous rules in a ruleset (for diagnostic / warning purposes).
 */
export function findDangerousRules(ruleset: PermissionRule[]): PermissionRule[] {
    return ruleset.filter(isDangerousRule)
}
