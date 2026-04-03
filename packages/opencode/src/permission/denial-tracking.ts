/**
 * Denial tracking for the AI permission classifier.
 *
 * Tracks consecutive and total denials to determine when the classifier
 * should stop trying and fall back to prompting the user directly.
 *
 * This prevents infinite classification loops when the model consistently
 * blocks actions that the user actually wants to perform.
 *
 * Reference: Claude Code denialTracking.ts
 */

export namespace DenialTracker {
    const DEFAULT_CONSECUTIVE_THRESHOLD = 3
    const DEFAULT_TOTAL_THRESHOLD = 20

    let consecutive = 0
    let total = 0
    let consecutiveThreshold = DEFAULT_CONSECUTIVE_THRESHOLD
    let totalThreshold = DEFAULT_TOTAL_THRESHOLD

    /**
     * Configure custom thresholds (from user config).
     */
    export function configure(opts: { consecutive?: number; total?: number }): void {
        if (opts.consecutive !== undefined) consecutiveThreshold = opts.consecutive
        if (opts.total !== undefined) totalThreshold = opts.total
    }

    /**
     * Record a denial (classifier blocked an action and user was prompted).
     */
    export function recordDenial(): void {
        consecutive++
        total++
    }

    /**
     * Record a successful approval (classifier allowed an action).
     * Resets the consecutive denial counter.
     */
    export function recordApproval(): void {
        consecutive = 0
    }

    /**
     * Check if the denial threshold has been reached.
     * When true, the classifier should be bypassed entirely.
     */
    export function shouldEscalate(): boolean {
        return consecutive >= consecutiveThreshold || total >= totalThreshold
    }

    /**
     * Reset all tracking state (e.g. on new session or mode change).
     */
    export function reset(): void {
        consecutive = 0
        total = 0
    }

    /**
     * Get current tracking stats (for logging/debugging).
     */
    export function stats(): { consecutive: number; total: number } {
        return { consecutive, total }
    }
}
