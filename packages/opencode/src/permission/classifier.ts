/**
 * AI Permission Classifier — Core classification service.
 *
 * Two-stage LLM classification pipeline that auto-approves safe tool calls
 * in auto mode, reducing manual user approvals.
 *
 * Architecture:
 * - Stage 1 (fast): max_tokens=64, binary allow/block
 * - Stage 2 (deep): max_tokens=1024, chain-of-thought reasoning
 * - Fail-closed: any error → escalate to user
 *
 * Uses Vercel AI SDK generateObject() with Zod schemas for structured output.
 * Compatible with all providers supported by OpenCode (not Anthropic-specific).
 *
 * Reference: Claude Code yoloClassifier.ts (redesigned for OpenCode architecture)
 */

import { generateObject } from "ai"
import z from "zod"
import path from "path"
import fs from "fs"
import os from "os"
import { Provider } from "@/provider/provider"
import { Config } from "@/config/config"
import { Log } from "@/util/log"
import { SAFE_TOOL_ALLOWLIST, isDangerousBashCommand, HIGH_RISK_PERMISSIONS, isCodeExecCommand } from "./classifier-allowlist"
import { DenialTracker } from "./denial-tracking"
import { ClassifierPrompts, type ClassifierPromptInput } from "./classifier-prompt"

export namespace Classifier {
    const log = Log.create({ service: "permission.classifier" })

    // ── Response schemas for generateObject() ──

    const Stage1Response = z.object({
        decision: z.enum(["allow", "block"]),
    })

    const Stage2Response = z.object({
        reasoning: z.string(),
        decision: z.enum(["allow", "block"]),
    })

    // ── Public types ──

    export type Decision = "allow" | "block" | "escalate"

    export interface ClassifyInput {
        /** Permission type (bash, edit, read, etc.) */
        permission: string
        /** Specific patterns (file paths, commands, URLs) */
        patterns: string[]
        /** Tool-specific context (diff, filepath, command args, etc.) */
        metadata: Record<string, any>
        /** Tool name, used for allowlist check */
        toolName?: string
        /** Recent conversation context for Stage 2 reasoning */
        sessionContext?: Array<{ role: string; summary: string }>
    }

    export interface ClassifyResult {
        /** Final decision: allow (auto-approve), escalate (ask user) */
        decision: Decision
        /** Reasoning from Stage 2 (if reached) */
        reasoning?: string
        /** Which stage produced the final decision */
        stage: 0 | 1 | 2
        /** Total classifier wall-clock time in ms */
        durationMs: number
    }

    // ── Core classification entry point ──

    /**
     * Classify a tool action as safe (allow) or needing user review (escalate).
     *
     * This function never throws — all errors are caught and result in "escalate".
     * It also never returns "deny" — only the rule system has that authority.
     *
     * Flow:
     * 1. Check if classifier is enabled
     * 2. User blocklist override (highest priority)
     * 3. Safe tool allowlist fast-path
     * 4. User allowlist override
     * 5. Dangerous pattern hard block
     * 6. Code execution prefix detection
     * 7. Denial threshold check
     * 8. Stage 1 (fast classification)
     * 9. Stage 2 (deep classification, only if Stage 1 blocks)
     */
    export async function classify(input: ClassifyInput): Promise<ClassifyResult> {
        try {
            const cfg = await Config.get()
            const classifierCfg = cfg.classifier

            // 0. Check if classifier is enabled
            if (!classifierCfg?.enabled) {
                return { decision: "escalate", stage: 0, durationMs: 0 }
            }

            // 1. User blocklist override → always escalate (highest priority)
            if (input.toolName && classifierCfg.blocklist_override?.includes(input.toolName)) {
                log.info("blocklisted by config override", { tool: input.toolName })
                return { decision: "escalate", stage: 0, durationMs: 0 }
            }
            // Also check permission type in blocklist (e.g. "edit", "bash")
            if (classifierCfg.blocklist_override?.includes(input.permission)) {
                log.info("permission blocklisted by config override", { permission: input.permission })
                return { decision: "escalate", stage: 0, durationMs: 0 }
            }

            // 2. Safe tool allowlist → auto-allow without LLM call
            if (input.toolName && SAFE_TOOL_ALLOWLIST.has(input.toolName)) {
                log.info("allowlisted", { tool: input.toolName })
                return { decision: "allow", stage: 0, durationMs: 0 }
            }

            // 3. User allowlist override → auto-allow without LLM call
            if (input.toolName && classifierCfg.allowlist_override?.includes(input.toolName)) {
                log.info("allowlisted by config override", { tool: input.toolName })
                return { decision: "allow", stage: 0, durationMs: 0 }
            }
            if (classifierCfg.allowlist_override?.includes(input.permission)) {
                log.info("permission allowlisted by config override", { permission: input.permission })
                return { decision: "allow", stage: 0, durationMs: 0 }
            }

            // 4. Dangerous bash pattern → always escalate
            if (input.permission === "bash" && input.metadata?.command) {
                if (isDangerousBashCommand(String(input.metadata.command))) {
                    log.info("dangerous pattern detected, escalating", {
                        command: String(input.metadata.command).slice(0, 100),
                    })
                    return { decision: "escalate", stage: 0, durationMs: 0 }
                }
            }

            // 5. Code execution prefix detection — mark for conservative classification
            let isCodeExec = false
            if (input.permission === "bash" && input.metadata?.command) {
                isCodeExec = isCodeExecCommand(String(input.metadata.command))
                if (isCodeExec) {
                    log.info("code execution prefix detected, will classify conservatively", {
                        command: String(input.metadata.command).slice(0, 100),
                    })
                }
            }

            // 6. Configure and check denial tracking thresholds
            if (classifierCfg.denial_threshold) {
                DenialTracker.configure({
                    consecutive: classifierCfg.denial_threshold.consecutive,
                    total: classifierCfg.denial_threshold.total,
                })
            }
            if (DenialTracker.shouldEscalate()) {
                log.info("denial threshold reached, escalating", DenialTracker.stats())
                return { decision: "escalate", stage: 0, durationMs: 0 }
            }

            // 7. Obtain small model for classification
            const language = await getClassifierModel(classifierCfg)
            if (!language) {
                log.warn("no classifier model available, escalating")
                return { decision: "escalate", stage: 0, durationMs: 0 }
            }

            const timeout = classifierCfg.timeout ?? 5000

            // Enrich input with code execution flag for prompts
            const enrichedInput: ClassifyInput = isCodeExec
                ? { ...input, metadata: { ...input.metadata, _codeExec: true } }
                : input

            // 8. Stage 1: Fast classification
            const start1 = Date.now()
            const stage1Result = await runStage1(language, enrichedInput, timeout)
            const duration1 = Date.now() - start1

            log.info("stage1", {
                decision: stage1Result.decision,
                duration: duration1,
                permission: input.permission,
                toolName: input.toolName,
                patterns: input.patterns,
                isCodeExec,
            })

            if (stage1Result.decision === "allow") {
                DenialTracker.recordApproval()
                return { decision: "allow", stage: 1, durationMs: duration1 }
            }

            // 9. Stage 2: Deep classification (Stage 1 blocked)
            const stage2Timeout = Math.max(timeout * 2, 10000)
            const start2 = Date.now()
            const stage2Result = await runStage2(language, enrichedInput, stage2Timeout)
            const duration2 = Date.now() - start2
            const totalDuration = duration1 + duration2

            log.info("stage2", {
                decision: stage2Result.decision,
                reasoning: stage2Result.reasoning?.slice(0, 200),
                duration: duration2,
                permission: input.permission,
                toolName: input.toolName,
                isCodeExec,
            })

            if (stage2Result.decision === "allow") {
                DenialTracker.recordApproval()
                return {
                    decision: "allow",
                    reasoning: stage2Result.reasoning,
                    stage: 2,
                    durationMs: totalDuration,
                }
            }

            // Both stages blocked → escalate to user (not deny!)
            DenialTracker.recordDenial()
            return {
                decision: "escalate",
                reasoning: stage2Result.reasoning,
                stage: 2,
                durationMs: totalDuration,
            }
        } catch (err) {
            // ── Fail-closed: any error → escalate to user ──
            log.warn("classifier error, escalating", { error: String(err) })
            dumpClassifierError(input, err)
            return { decision: "escalate", stage: 0, durationMs: 0 }
        }
    }

    /**
     * Reset classifier state (call on session change or mode toggle).
     */
    export function reset(): void {
        DenialTracker.reset()
    }

    // ── Private helpers ──

    /**
     * Obtain the LanguageModel to use for classification.
     * Priority: classifier.model config → Provider.getSmallModel()
     */
    async function getClassifierModel(
        classifierCfg: NonNullable<Config.Info["classifier"]>,
    ) {
        try {
            // User-specified classifier model
            if (classifierCfg.model) {
                const parsed = Provider.parseModel(classifierCfg.model)
                const model = await Provider.getModel(parsed.providerID, parsed.modelID)
                return Provider.getLanguage(model)
            }

            // Fall back to small model from default provider
            const defaults = await Provider.defaultModel()
            const smallModel = await Provider.getSmallModel(defaults.providerID)
            if (!smallModel) return undefined
            return Provider.getLanguage(smallModel)
        } catch {
            return undefined
        }
    }

    /**
     * Stage 1: Fast binary classification.
     * max_tokens=64, temperature=0, minimal context.
     */
    async function runStage1(
        language: Awaited<ReturnType<typeof Provider.getLanguage>>,
        input: ClassifyInput,
        timeoutMs: number,
    ): Promise<z.infer<typeof Stage1Response>> {
        const promptInput: ClassifierPromptInput = {
            permission: input.permission,
            patterns: input.patterns,
            metadata: input.metadata,
            toolName: input.toolName,
            sessionContext: input.sessionContext,
        }

        const ctrl = new AbortController()
        const timer = setTimeout(() => ctrl.abort(), timeoutMs)

        try {
            const result = await generateObject({
                model: language,
                schema: Stage1Response,
                temperature: 0,
                maxOutputTokens: 64,
                messages: [
                    { role: "system", content: ClassifierPrompts.system },
                    { role: "user", content: ClassifierPrompts.stage1(promptInput) },
                ],
                abortSignal: ctrl.signal,
            })
            return result.object
        } finally {
            clearTimeout(timer)
        }
    }

    /**
     * Stage 2: Deep classification with chain-of-thought reasoning.
     * max_tokens=2048, temperature=0, full context.
     */
    async function runStage2(
        language: Awaited<ReturnType<typeof Provider.getLanguage>>,
        input: ClassifyInput,
        timeoutMs: number,
    ): Promise<z.infer<typeof Stage2Response>> {
        const promptInput: ClassifierPromptInput = {
            permission: input.permission,
            patterns: input.patterns,
            metadata: input.metadata,
            toolName: input.toolName,
            sessionContext: input.sessionContext,
        }

        const ctrl = new AbortController()
        const timer = setTimeout(() => ctrl.abort(), timeoutMs)

        try {
            const result = await generateObject({
                model: language,
                schema: Stage2Response,
                temperature: 0,
                maxOutputTokens: 2048,
                messages: [
                    { role: "system", content: ClassifierPrompts.system },
                    { role: "user", content: ClassifierPrompts.stage2(promptInput) },
                ],
                abortSignal: ctrl.signal,
            })
            return result.object
        } finally {
            clearTimeout(timer)
        }
    }

    /**
     * Dump classifier error details to disk for debugging.
     * Saves to ~/.config/opencode/classifier-errors/{timestamp}.json
     */
    function dumpClassifierError(input: ClassifyInput, err: unknown): void {
        try {
            const errorDir = path.join(os.homedir(), ".config", "opencode", "classifier-errors")
            fs.mkdirSync(errorDir, { recursive: true })
            const filename = `${new Date().toISOString().replace(/[:.]/g, "-")}.json`
            const filepath = path.join(errorDir, filename)
            const dump = {
                timestamp: new Date().toISOString(),
                input: {
                    permission: input.permission,
                    patterns: input.patterns,
                    toolName: input.toolName,
                    metadata: Object.fromEntries(
                        Object.entries(input.metadata).map(([k, v]) => [
                            k,
                            typeof v === "string" ? v.slice(0, 500) : v,
                        ]),
                    ),
                },
                error: String(err),
                stack: err instanceof Error ? err.stack : undefined,
            }
            fs.writeFileSync(filepath, JSON.stringify(dump, null, 2), "utf-8")
            log.info("classifier error dumped", { filepath })
        } catch {
            // Silently ignore dump errors — don't let logging break the flow
        }
    }
}
