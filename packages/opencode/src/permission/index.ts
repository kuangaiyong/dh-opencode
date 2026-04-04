import { Bus } from "@/bus"
import { BusEvent } from "@/bus/bus-event"
import { Config } from "@/config/config"
import { InstanceState } from "@/effect/instance-state"
import { makeRuntime } from "@/effect/run-service"
import { ProjectID } from "@/project/schema"
import { Instance } from "@/project/instance"
import { MessageID, SessionID } from "@/session/schema"
import { PermissionTable } from "@/session/session.sql"
import { Database, eq } from "@/storage/db"
import { Log } from "@/util/log"
import { Wildcard } from "@/util/wildcard"
import { Deferred, Effect, Layer, Schema, ServiceMap } from "effect"
import os from "os"
import path from "path"
import z from "zod"
import { evaluate as evalRule } from "./evaluate"
import { PermissionID } from "./schema"
import { Classifier } from "./classifier"
import { MessageV2 } from "@/session/message-v2"
import { checkPathsSafety } from "@/security/path-safety"
import { stripDangerousRules } from "@/permission/dangerous-rules"

export namespace Permission {
  const log = Log.create({ service: "permission" })

  export const Action = z.enum(["allow", "deny", "ask"]).meta({
    ref: "PermissionAction",
  })
  export type Action = z.infer<typeof Action>

  export const Rule = z
    .object({
      permission: z.string(),
      pattern: z.string(),
      action: Action,
    })
    .meta({
      ref: "PermissionRule",
    })
  export type Rule = z.infer<typeof Rule>

  export const Ruleset = Rule.array().meta({
    ref: "PermissionRuleset",
  })
  export type Ruleset = z.infer<typeof Ruleset>

  export const Request = z
    .object({
      id: PermissionID.zod,
      sessionID: SessionID.zod,
      permission: z.string(),
      patterns: z.string().array(),
      metadata: z.record(z.string(), z.any()),
      always: z.string().array(),
      toolName: z.string().optional(),
      tool: z
        .object({
          messageID: MessageID.zod,
          callID: z.string(),
        })
        .optional(),
    })
    .meta({
      ref: "PermissionRequest",
    })
  export type Request = z.infer<typeof Request>

  export const Reply = z.enum(["once", "always", "reject"])
  export type Reply = z.infer<typeof Reply>

  export const Approval = z.object({
    projectID: ProjectID.zod,
    patterns: z.string().array(),
  })

  export const Event = {
    Asked: BusEvent.define("permission.asked", Request),
    Replied: BusEvent.define(
      "permission.replied",
      z.object({
        sessionID: SessionID.zod,
        requestID: PermissionID.zod,
        reply: Reply,
      }),
    ),
  }

  export class RejectedError extends Schema.TaggedErrorClass<RejectedError>()("PermissionRejectedError", {}) {
    override get message() {
      return "The user rejected permission to use this specific tool call."
    }
  }

  export class CorrectedError extends Schema.TaggedErrorClass<CorrectedError>()("PermissionCorrectedError", {
    feedback: Schema.String,
  }) {
    override get message() {
      return `The user rejected permission to use this specific tool call with the following feedback: ${this.feedback}`
    }
  }

  export class DeniedError extends Schema.TaggedErrorClass<DeniedError>()("PermissionDeniedError", {
    ruleset: Schema.Any,
  }) {
    override get message() {
      return `The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules ${JSON.stringify(this.ruleset)}`
    }
  }

  export type Error = DeniedError | RejectedError | CorrectedError

  export const AskInput = Request.partial({ id: true }).extend({
    ruleset: Ruleset,
  })

  export const ReplyInput = z.object({
    requestID: PermissionID.zod,
    reply: Reply,
    message: z.string().optional(),
  })

  export interface Interface {
    readonly ask: (input: z.infer<typeof AskInput>) => Effect.Effect<void, Error>
    readonly reply: (input: z.infer<typeof ReplyInput>) => Effect.Effect<void>
    readonly list: () => Effect.Effect<Request[]>
  }

  interface PendingEntry {
    info: Request
    deferred: Deferred.Deferred<void, RejectedError | CorrectedError>
  }

  interface State {
    pending: Map<PermissionID, PendingEntry>
    approved: Ruleset
  }

  export function evaluate(permission: string, pattern: string, ...rulesets: Ruleset[]): Rule {
    log.info("evaluate", { permission, pattern, ruleset: rulesets.flat() })
    return evalRule(permission, pattern, ...rulesets)
  }

  export class Service extends ServiceMap.Service<Service, Interface>()("@opencode/Permission") {}

  export const layer = Layer.effect(
    Service,
    Effect.gen(function* () {
      const state = yield* InstanceState.make<State>(
        Effect.fn("Permission.state")(function* (ctx) {
          const row = Database.use((db) =>
            db.select().from(PermissionTable).where(eq(PermissionTable.project_id, ctx.project.id)).get(),
          )
          const state = {
            pending: new Map<PermissionID, PendingEntry>(),
            approved: row?.data ?? [],
          }

          yield* Effect.addFinalizer(() =>
            Effect.gen(function* () {
              for (const item of state.pending.values()) {
                yield* Deferred.fail(item.deferred, new RejectedError())
              }
              state.pending.clear()
            }),
          )

          return state
        }),
      )

      const ask = Effect.fn("Permission.ask")(function* (input: z.infer<typeof AskInput>) {
        const { approved, pending } = yield* InstanceState.get(state)
        const { ruleset, ...request } = input
        let needsAsk = false

        // ── Dangerous rule stripping: prevent overly broad allow rules from bypassing classifier ──
        // When the AI classifier is enabled, rules like `bash: * → allow` or
        // `bash: python * → allow` would short-circuit to "allow" before the
        // classifier gets a chance to evaluate safety. Strip these rules so
        // the classifier can do its job.
        // NOTE: Only strips from the config/project ruleset, NOT from `approved`
        // (session-level rules the user explicitly approved are always honored).
        let effectiveRuleset = ruleset
        const classifierCfg = yield* Effect.tryPromise({
          try: async () => {
            const cfg = await Config.get()
            return cfg.classifier?.enabled === true
          },
          catch: () => false, // fail-open: if config fails, don't strip rules
        })
        if (classifierCfg) {
          effectiveRuleset = stripDangerousRules(ruleset)
          if (effectiveRuleset !== ruleset) {
            log.info("stripped dangerous rules from ruleset for classifier safety", {
              original: ruleset.length,
              filtered: effectiveRuleset.length,
            })
          }
        }

        for (const pattern of request.patterns) {
          const rule = evaluate(request.permission, pattern, effectiveRuleset, approved)
          log.info("evaluated", { permission: request.permission, pattern, action: rule })
          if (rule.action === "deny") {
            return yield* new DeniedError({
              ruleset: ruleset.filter((rule) => Wildcard.match(request.permission, rule.permission)),
            })
          }
          if (rule.action === "allow") continue
          needsAsk = true
        }

        if (!needsAsk) return

        // ── Path Safety: block dangerous paths before acceptEdits / classifier ──
        // Reference: Claude Code filesystem.ts checkPathSafetyForAutoEdit
        // Checks for: dangerous files (.bashrc, .gitconfig), dangerous dirs (.git, .vscode),
        // Windows NTFS attacks (ADS, 8.3 shortnames, device names), UNC paths, etc.
        let skipAcceptEdits = false
        let skipClassifier = false
        const pathSafetyEnabled = yield* Effect.tryPromise({
          try: async () => {
            const cfg = await Config.get()
            return cfg.experimental?.path_safety !== false // default: enabled
          },
          catch: () => true, // fail-closed: treat as enabled
        })
        if (pathSafetyEnabled) {
          const pathResult = checkPathsSafety(request.patterns)
          if (!pathResult.safe) {
            log.info("path safety check failed", {
              message: pathResult.message,
              classifierApprovable: pathResult.classifierApprovable,
              patterns: request.patterns,
            })
            skipAcceptEdits = true
            if (!pathResult.classifierApprovable) {
              skipClassifier = true
            }
          }
        }

        // ── Bash Security: check if bash tool flagged the command as unsafe ──
        // When metadata.bashSecurityMessage is set, the bash command failed
        // security validation. Skip classifier for misparsing exploits.
        if (request.metadata?.bashSecurityMessage) {
          log.info("bash security metadata present, skipping acceptEdits", {
            message: request.metadata.bashSecurityMessage,
          })
          skipAcceptEdits = true
          // Misparsing exploits (parser differential attacks) should never be
          // auto-approved by the classifier — always escalate to user.
          skipClassifier = true
        }

        // ── acceptEdits fast path: auto-approve file edits within project directory ──
        // Reference: Claude Code permissions.ts acceptEdits fast path
        // This avoids unnecessary LLM classifier calls for normal project file edits.
        // SECURITY: Skipped when path safety or bash security flags the request.
        const ACCEPT_EDITS_TOOLS = new Set(["edit", "write", "apply_patch", "multiedit"])
        if (
          !skipAcceptEdits &&
          request.permission === "edit" &&
          request.toolName &&
          ACCEPT_EDITS_TOOLS.has(request.toolName)
        ) {
          const worktree = Instance.worktree
          // SECURITY: Non-git projects set worktree to "/" (or "\" on Windows).
          // Skip fast path entirely in this case — otherwise ALL absolute paths
          // would be auto-approved since everything starts with "/".
          if (worktree !== "/" && worktree !== "\\") {
            const allInProject = request.patterns.every((p) => {
              // Relative paths are inherently within the project
              if (!path.isAbsolute(p)) return true
              // Absolute paths must be within the project worktree
              const normalized = path.normalize(p)
              return normalized.startsWith(path.normalize(worktree))
            })
            if (allInProject) {
              log.info("acceptEdits fast path: project-local edit auto-approved", {
                toolName: request.toolName,
                patterns: request.patterns,
              })
              return
            }
          }
        }

        // ── AI Classifier: attempt to auto-approve safe tool calls ──
        // SECURITY: Skipped when path safety or bash security flags classifierApprovable=false
        // (e.g. NTFS attack patterns, parser differential exploits).

        // Fetch recent session context for the classifier (best-effort, non-blocking)
        let sessionContext: Array<{ role: string; summary: string }> | undefined
        if (!skipClassifier) {
          const sessionContextResult = yield* Effect.tryPromise({
            try: () =>
              MessageV2.page({
                sessionID: request.sessionID,
                limit: 10,
              }),
            catch: () => undefined,
          }).pipe(Effect.option)

          if (sessionContextResult._tag === "Some" && sessionContextResult.value) {
            const recentMessages = sessionContextResult.value
            if (recentMessages.items.length > 0) {
              sessionContext = recentMessages.items
                .map((msg) => {
                  const role = msg.info.role
                  // Extract text content as summary
                  const textParts = msg.parts
                    .filter((p): p is MessageV2.TextPart => p.type === "text")
                    .map((p) => p.text)
                  const summary = textParts.join(" ").slice(0, 300) || `[${role} message]`
                  return { role, summary }
                })
                .slice(-5) // Keep last 5 messages
            }
          }
        }

        if (!skipClassifier) {
          const classifyResult = yield* Effect.tryPromise({
            try: () =>
              Classifier.classify({
                permission: request.permission,
                patterns: request.patterns,
                metadata: request.metadata,
                toolName: request.toolName,
                sessionContext,
              }),
            catch: () => "classifier-error" as const,
          }).pipe(Effect.option)

          if (classifyResult._tag === "Some" && classifyResult.value.decision === "allow") {
            log.info("classifier auto-approved", {
              permission: request.permission,
              patterns: request.patterns,
              toolName: request.toolName,
              stage: classifyResult.value.stage,
              durationMs: classifyResult.value.durationMs,
              reasoning: classifyResult.value.reasoning?.slice(0, 200),
            })
            return
          }
          if (classifyResult._tag === "Some") {
            log.info("classifier escalated to user", {
              permission: request.permission,
              patterns: request.patterns,
              toolName: request.toolName,
              decision: classifyResult.value.decision,
              stage: classifyResult.value.stage,
              durationMs: classifyResult.value.durationMs,
              reasoning: classifyResult.value.reasoning?.slice(0, 200),
            })
          }
          if (classifyResult._tag === "None") {
            log.warn("classifier returned no result (error), falling back to user prompt", {
              permission: request.permission,
              toolName: request.toolName,
            })
          }
        } else {
          log.info("classifier skipped due to security checks (non-classifier-approvable)", {
            permission: request.permission,
            patterns: request.patterns,
          })
        }

        const id = request.id ?? PermissionID.ascending()
        const info: Request = {
          id,
          ...request,
        }
        log.info("asking", { id, permission: info.permission, patterns: info.patterns })

        const deferred = yield* Deferred.make<void, RejectedError | CorrectedError>()
        pending.set(id, { info, deferred })
        void Bus.publish(Event.Asked, info)
        return yield* Effect.ensuring(
          Deferred.await(deferred),
          Effect.sync(() => {
            pending.delete(id)
          }),
        )
      })

      const reply = Effect.fn("Permission.reply")(function* (input: z.infer<typeof ReplyInput>) {
        const { approved, pending } = yield* InstanceState.get(state)
        const existing = pending.get(input.requestID)
        if (!existing) return

        pending.delete(input.requestID)
        void Bus.publish(Event.Replied, {
          sessionID: existing.info.sessionID,
          requestID: existing.info.id,
          reply: input.reply,
        })

        if (input.reply === "reject") {
          yield* Deferred.fail(
            existing.deferred,
            input.message ? new CorrectedError({ feedback: input.message }) : new RejectedError(),
          )

          for (const [id, item] of pending.entries()) {
            if (item.info.sessionID !== existing.info.sessionID) continue
            pending.delete(id)
            void Bus.publish(Event.Replied, {
              sessionID: item.info.sessionID,
              requestID: item.info.id,
              reply: "reject",
            })
            yield* Deferred.fail(item.deferred, new RejectedError())
          }
          return
        }

        yield* Deferred.succeed(existing.deferred, undefined)
        if (input.reply === "once") return

        for (const pattern of existing.info.always) {
          approved.push({
            permission: existing.info.permission,
            pattern,
            action: "allow",
          })
        }

        for (const [id, item] of pending.entries()) {
          if (item.info.sessionID !== existing.info.sessionID) continue
          const ok = item.info.patterns.every(
            (pattern) => evaluate(item.info.permission, pattern, approved).action === "allow",
          )
          if (!ok) continue
          pending.delete(id)
          void Bus.publish(Event.Replied, {
            sessionID: item.info.sessionID,
            requestID: item.info.id,
            reply: "always",
          })
          yield* Deferred.succeed(item.deferred, undefined)
        }
      })

      const list = Effect.fn("Permission.list")(function* () {
        const pending = (yield* InstanceState.get(state)).pending
        return Array.from(pending.values(), (item) => item.info)
      })

      return Service.of({ ask, reply, list })
    }),
  )

  function expand(pattern: string): string {
    if (pattern.startsWith("~/")) return os.homedir() + pattern.slice(1)
    if (pattern === "~") return os.homedir()
    if (pattern.startsWith("$HOME/")) return os.homedir() + pattern.slice(5)
    if (pattern === "$HOME") return os.homedir()
    return pattern
  }

  export function fromConfig(permission: Config.Permission) {
    const ruleset: Ruleset = []
    for (const [key, value] of Object.entries(permission)) {
      if (typeof value === "string") {
        ruleset.push({ permission: key, action: value, pattern: "*" })
        continue
      }
      ruleset.push(
        ...Object.entries(value).map(([pattern, action]) => ({ permission: key, pattern: expand(pattern), action })),
      )
    }
    return ruleset
  }

  export function merge(...rulesets: Ruleset[]): Ruleset {
    return rulesets.flat()
  }

  const EDIT_TOOLS = ["edit", "write", "apply_patch", "multiedit"]

  export function disabled(tools: string[], ruleset: Ruleset): Set<string> {
    const result = new Set<string>()
    for (const tool of tools) {
      const permission = EDIT_TOOLS.includes(tool) ? "edit" : tool
      const rule = ruleset.findLast((rule) => Wildcard.match(permission, rule.permission))
      if (!rule) continue
      if (rule.pattern === "*" && rule.action === "deny") result.add(tool)
    }
    return result
  }

  export const { runPromise } = makeRuntime(Service, layer)

  export async function ask(input: z.infer<typeof AskInput>) {
    return runPromise((s) => s.ask(input))
  }

  export async function reply(input: z.infer<typeof ReplyInput>) {
    return runPromise((s) => s.reply(input))
  }

  export async function list() {
    return runPromise((s) => s.list())
  }
}
