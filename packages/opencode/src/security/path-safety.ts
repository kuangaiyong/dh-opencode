/**
 * Path Safety Module
 *
 * Checks whether a file path is safe for auto-editing (acceptEdits / classifier approval).
 * Ported from Claude Code `utils/permissions/filesystem.ts`.
 *
 * Key protections:
 * - Dangerous files (.bashrc, .gitconfig, etc.) that enable code execution / data exfiltration
 * - Dangerous directories (.git, .vscode, .idea, .claude) containing sensitive config
 * - Windows NTFS attack vectors (Alternate Data Streams, 8.3 shortnames, device names, etc.)
 * - UNC paths (network resource access, credential leaking)
 * - Path traversal via triple-dots
 *
 * Design principles:
 * - Pure functions, no Effect dependency — callable from any context
 * - Case-insensitive comparisons on all platforms (defense-in-depth for mounted NTFS)
 * - Fail-open by default (returns safe:true when module is disabled)
 */

import path from "path"
import os from "os"

// ─── Dangerous File / Directory Lists ───────────────────────────────────────

/**
 * Dangerous files that should be protected from auto-editing.
 * These files can be used for code execution or data exfiltration.
 */
export const DANGEROUS_FILES = [
    ".gitconfig",
    ".gitmodules",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".ripgreprc",
    ".mcp.json",
    // OpenCode specific
    "opencode.json",
] as const

/**
 * Dangerous directories that should be protected from auto-editing.
 * These directories contain sensitive configuration or executable files.
 */
export const DANGEROUS_DIRECTORIES = [
    ".git",
    ".vscode",
    ".idea",
    ".claude",
    // OpenCode specific
    ".opencode",
] as const

// ─── Utility ────────────────────────────────────────────────────────────────

/**
 * Normalizes a path for case-insensitive comparison.
 * Prevents bypassing security checks using mixed-case paths on case-insensitive
 * filesystems (macOS/Windows) like `.cLauDe/Settings.locaL.json`.
 */
function normalizeCaseForComparison(p: string): string {
    return p.toLowerCase()
}

/**
 * Returns the platform identifier, accounting for WSL.
 * "windows" | "wsl" | "posix"
 */
function getPlatformKind(): "windows" | "wsl" | "posix" {
    if (process.platform === "win32") return "windows"
    // Detect WSL by checking for Microsoft in the kernel version
    try {
        if (os.release().toLowerCase().includes("microsoft")) return "wsl"
    } catch {
        // Ignore — fall through to posix
    }
    return "posix"
}

// ─── Core Checks ────────────────────────────────────────────────────────────

/**
 * Check if a file path points to a dangerous file or resides inside a dangerous directory.
 *
 * Checks:
 * 1. UNC paths (\\server\share, //server/share)
 * 2. Path segments matching DANGEROUS_DIRECTORIES (case-insensitive)
 * 3. Filename matching DANGEROUS_FILES (case-insensitive)
 */
function isDangerousFilePath(filePath: string): boolean {
    const normalized = path.normalize(path.resolve(filePath))
    const segments = normalized.split(path.sep)
    const fileName = segments.at(-1)

    // Check for UNC paths — block \\... and //... prefixes
    if (filePath.startsWith("\\\\") || filePath.startsWith("//")) {
        return true
    }

    // Check dangerous directories (case-insensitive)
    for (const segment of segments) {
        const lower = normalizeCaseForComparison(segment)
        for (const dir of DANGEROUS_DIRECTORIES) {
            if (lower === normalizeCaseForComparison(dir)) {
                return true
            }
        }
    }

    // Check dangerous files (case-insensitive)
    if (fileName) {
        const lowerFileName = normalizeCaseForComparison(fileName)
        for (const file of DANGEROUS_FILES) {
            if (lowerFileName === normalizeCaseForComparison(file)) {
                return true
            }
        }
    }

    return false
}

/**
 * Detects suspicious Windows path patterns that could bypass security checks.
 *
 * Checks:
 * - NTFS Alternate Data Streams (file.txt::$DATA, file.txt:stream)  [Windows/WSL only]
 * - 8.3 short names (GIT~1, CLAUDE~1, SETTIN~1.JSON)
 * - Long path prefixes (\\?\C:\..., \\.\C:\..., //?/C:/..., //./C:/...)
 * - Trailing dots and spaces (.git., .claude )
 * - DOS device names (.git.CON, settings.json.PRN)
 * - Three or more consecutive dots as a path component (.../file.txt)
 * - UNC paths (\\server\share, //server/share)
 *
 * Why check on all platforms?
 * NTFS filesystems can be mounted on Linux/macOS (ntfs-3g). 8.3 shortnames,
 * long path prefixes, trailing dots, DOS devices, triple-dots, and UNC paths
 * are checked everywhere for defense-in-depth. Only ADS colon syntax is
 * Windows/WSL-specific (the kernel interprets it).
 */
function hasSuspiciousWindowsPathPattern(filePath: string): boolean {
    const platform = getPlatformKind()

    // NTFS Alternate Data Streams — colon after position 2 (skip drive letter C:\)
    // Only meaningful on Windows and WSL (where DrvFs routes through Windows kernel)
    if (platform === "windows" || platform === "wsl") {
        const colonIndex = filePath.indexOf(":", 2)
        if (colonIndex !== -1) {
            return true
        }
    }

    // 8.3 short names — tilde followed by a digit
    if (/~\d/.test(filePath)) {
        return true
    }

    // Long path prefixes
    if (
        filePath.startsWith("\\\\?\\") ||
        filePath.startsWith("\\\\.\\") ||
        filePath.startsWith("//?/") ||
        filePath.startsWith("//./")
    ) {
        return true
    }

    // Trailing dots and spaces that Windows strips during path resolution
    if (/[.\s]+$/.test(filePath)) {
        return true
    }

    // DOS device names
    if (/\.(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i.test(filePath)) {
        return true
    }

    // Three or more consecutive dots as a path component
    if (/(^|\/|\\)\.{3,}(\/|\\|$)/.test(filePath)) {
        return true
    }

    // UNC paths (defense-in-depth, also covered by isDangerousFilePath)
    if (filePath.startsWith("\\\\") || filePath.startsWith("//")) {
        return true
    }

    return false
}

// ─── Public API ─────────────────────────────────────────────────────────────

export type PathSafetyResult =
    | { safe: true }
    | { safe: false; message: string; classifierApprovable: boolean }

/**
 * Check whether a file path is safe for auto-editing.
 *
 * Returns `{ safe: true }` if all checks pass.
 * Returns `{ safe: false, message, classifierApprovable }` if the path is unsafe:
 * - `classifierApprovable: false` → must ask the user (e.g. NTFS attack patterns)
 * - `classifierApprovable: true`  → the AI classifier MAY still approve it
 *
 * @param filePath  The path to check (absolute or relative)
 * @returns         Safety result
 */
export function checkPathSafety(filePath: string): PathSafetyResult {
    // 1. Suspicious Windows patterns — always block (not classifier-approvable)
    if (hasSuspiciousWindowsPathPattern(filePath)) {
        return {
            safe: false,
            message: `Path "${filePath}" contains a suspicious Windows path pattern (NTFS streams, 8.3 names, long prefix, trailing dots, DOS device, or UNC). Manual approval required.`,
            classifierApprovable: false,
        }
    }

    // 2. Dangerous files / directories — classifier may still approve
    if (isDangerousFilePath(filePath)) {
        return {
            safe: false,
            message: `Path "${filePath}" targets a sensitive file or directory (.git, .bashrc, etc.). Requires explicit permission.`,
            classifierApprovable: true,
        }
    }

    return { safe: true }
}

/**
 * Batch-check multiple paths. Returns the first unsafe result, or { safe: true }.
 */
export function checkPathsSafety(paths: readonly string[]): PathSafetyResult {
    for (const p of paths) {
        const result = checkPathSafety(p)
        if (!result.safe) return result
    }
    return { safe: true }
}
