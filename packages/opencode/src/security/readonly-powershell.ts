/**
 * PowerShell Read-Only Command Auto-Approval Engine
 *
 * Validates whether a PowerShell command is purely read-only (no file writes,
 * no code execution, no network requests) and can be safely auto-approved.
 *
 * Ported from Claude Code's PowerShellTool/readOnlyValidation.ts (~1823 lines).
 * This is a simplified string/regex-based implementation — Claude Code uses
 * PowerShell AST parsing, but we avoid that dependency.
 *
 * Design decisions:
 * - Regex-based: no PowerShell AST parser dependency
 * - Fails closed: any ambiguity → NOT read-only → user prompt
 * - Dangerous constructs ($(), @splat, .Method(), ::static, --%, UNC) → reject
 * - Compound commands (pipes, ;) split and each sub-command checked
 * - Flag validation via explicit safe-flag sets per cmdlet
 * - Common PowerShell aliases resolved to canonical cmdlet names
 *
 * Reference: CC tools/PowerShellTool/readOnlyValidation.ts
 *            CC tools/PowerShellTool/commonParameters.ts
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export type ReadOnlyResult = {
  readonly: boolean
  reason?: string
}

type CmdletConfig = {
  /** Safe flags for this cmdlet (lowercase, with leading -). null = no flag validation */
  safeFlags?: string[]
  /** If true, all flags are safe (skip flag validation) */
  allowAllFlags?: boolean
  /** Custom danger check */
  isDangerous?: (raw: string) => boolean
}

// ─── Common Parameters (from CC commonParameters.ts) ─────────────────────────

/**
 * PowerShell common parameters available to all cmdlets with [CmdletBinding()].
 * These are always safe and don't need to be listed per-cmdlet.
 */
const COMMON_PARAMETERS = new Set([
  // Common switches
  "-verbose",
  "-debug",
  // Common value parameters
  "-erroraction",
  "-warningaction",
  "-informationaction",
  "-progressaction",
  "-errorvariable",
  "-warningvariable",
  "-informationvariable",
  "-outvariable",
  "-outbuffer",
  "-pipelinevariable",
])

// ─── PowerShell Alias Map ────────────────────────────────────────────────────

/**
 * Standard PowerShell aliases → canonical cmdlet names (lowercase).
 * Only includes aliases for cmdlets in our allowlist.
 */
const ALIASES: Record<string, string> = {
  // Navigation
  cd: "set-location",
  chdir: "set-location",
  sl: "set-location",
  pushd: "push-location",
  popd: "pop-location",
  pwd: "get-location",
  gl: "get-location",

  // File system
  ls: "get-childitem",
  dir: "get-childitem",
  gci: "get-childitem",
  cat: "get-content",
  gc: "get-content",
  type: "get-content",
  gi: "get-item",
  gp: "get-itemproperty",

  // Output
  echo: "write-output",
  write: "write-output",

  // Formatting / pipeline
  ft: "format-table",
  fl: "format-list",
  fw: "format-wide",
  fc: "format-custom",
  oh: "out-host",

  // Selection / filtering
  "?": "where-object",
  where: "where-object",
  "%": "foreach-object",
  foreach: "foreach-object",
  select: "select-object",
  sort: "sort-object",
  group: "group-object",
  measure: "measure-object",

  // Misc
  gal: "get-alias",
  gps: "get-process",
  gsv: "get-service",
  gm: "get-member",
  gmo: "get-module",
  ghy: "get-history",
  h: "get-history",
  history: "get-history",
  sleep: "start-sleep",
  tee: "tee-object",
}

// ─── Cmdlet Allowlist ────────────────────────────────────────────────────────

/**
 * Allowlisted PowerShell cmdlets and their safe flag configurations.
 *
 * Each cmdlet maps to a CmdletConfig that controls:
 * - safeFlags: explicit list of safe flags (case-insensitive)
 * - allowAllFlags: if true, skip flag validation entirely
 * - isDangerous: optional custom check for command-level danger
 *
 * Safety exclusions (NOT in allowlist):
 * - Get-Command: -Name triggers module auto-loading (runs .psm1 init code)
 * - Get-Help / man / help: same module auto-loading risk
 * - Select-Xml: XXE via XML external entities
 * - Test-Json: -Schema $ref can fetch external URLs
 * - Get-WmiObject / Get-CimInstance: Win32_PingStatus etc. make network requests
 * - Get-Clipboard: may expose sensitive clipboard data
 * - netsh: too complex to safely allowlist
 * - Invoke-*: code execution
 * - New-Object / Add-Type: .NET object creation
 */
const CMDLET_ALLOWLIST: Record<string, CmdletConfig> = Object.create(null) as Record<string, CmdletConfig>

// ── File system (read-only) ──
CMDLET_ALLOWLIST["get-childitem"] = {
  safeFlags: [
    "-path", "-literalpath", "-filter", "-include", "-exclude",
    "-recurse", "-depth", "-force", "-name", "-directory", "-file",
    "-hidden", "-readonly", "-system", "-attributes",
  ],
}
CMDLET_ALLOWLIST["get-content"] = {
  safeFlags: [
    "-path", "-literalpath", "-readcount", "-totalcount",
    "-tail", "-head", "-first", "-last", "-encoding",
    "-delimiter", "-wait", "-raw", "-stream",
  ],
}
CMDLET_ALLOWLIST["get-item"] = {
  safeFlags: ["-path", "-literalpath", "-filter", "-include", "-exclude", "-force", "-stream"],
}
CMDLET_ALLOWLIST["get-itemproperty"] = {
  safeFlags: ["-path", "-literalpath", "-name", "-filter", "-include", "-exclude"],
}
CMDLET_ALLOWLIST["test-path"] = {
  safeFlags: [
    "-path", "-literalpath", "-pathtype", "-isvalid",
    "-filter", "-include", "-exclude", "-olderthan", "-newerthan",
  ],
}
CMDLET_ALLOWLIST["resolve-path"] = {
  safeFlags: ["-path", "-literalpath", "-relative"],
}
CMDLET_ALLOWLIST["get-filehash"] = {
  safeFlags: ["-path", "-literalpath", "-algorithm"],
}
CMDLET_ALLOWLIST["get-acl"] = {
  safeFlags: ["-path", "-literalpath", "-filter", "-include", "-exclude"],
}

// ── Navigation ──
CMDLET_ALLOWLIST["set-location"] = {
  safeFlags: ["-path", "-literalpath", "-passthru", "-stackname"],
}
CMDLET_ALLOWLIST["push-location"] = {
  safeFlags: ["-path", "-literalpath", "-passthru", "-stackname"],
}
CMDLET_ALLOWLIST["pop-location"] = {
  safeFlags: ["-passthru", "-stackname"],
}

// ── Text search ──
CMDLET_ALLOWLIST["select-string"] = {
  safeFlags: [
    "-pattern", "-path", "-literalpath", "-simplematch",
    "-casesensitive", "-quiet", "-list", "-notmatch",
    "-include", "-exclude", "-allmatches", "-encoding",
    "-context", "-nonemphasis", "-raw",
  ],
}

// ── Data conversion ──
CMDLET_ALLOWLIST["convertto-json"] = {
  safeFlags: ["-inputobject", "-depth", "-compress", "-enumsalikestrings", "-asarray"],
}
CMDLET_ALLOWLIST["convertfrom-json"] = {
  safeFlags: ["-inputobject", "-depth", "-ashashtable", "-noenumsforstrings"],
}
CMDLET_ALLOWLIST["convertto-csv"] = {
  safeFlags: ["-inputobject", "-delimiter", "-notypeinformation", "-usequotes", "-includetypeinformation"],
}
CMDLET_ALLOWLIST["convertfrom-csv"] = {
  safeFlags: ["-inputobject", "-delimiter", "-header", "-usequotes"],
}
CMDLET_ALLOWLIST["convertto-xml"] = {
  safeFlags: ["-inputobject", "-depth", "-notypeinformation", "-as"],
}
CMDLET_ALLOWLIST["convertto-html"] = {
  safeFlags: [
    "-inputobject", "-property", "-body", "-head", "-title",
    "-as", "-cssuri", "-precontent", "-postcontent", "-fragment",
  ],
}
CMDLET_ALLOWLIST["format-hex"] = {
  safeFlags: ["-path", "-literalpath", "-inputobject", "-encoding", "-count", "-offset", "-raw"],
}

// ── Object inspection ──
CMDLET_ALLOWLIST["get-member"] = {
  safeFlags: ["-inputobject", "-membertype", "-name", "-force", "-static", "-view"],
}
CMDLET_ALLOWLIST["get-unique"] = {
  safeFlags: ["-inputobject", "-asstring", "-casesensitive", "-oninputobject"],
}
CMDLET_ALLOWLIST["compare-object"] = {
  safeFlags: [
    "-referenceobject", "-differenceobject", "-property",
    "-syncwindow", "-casesensitive", "-culture",
    "-includeequal", "-excludedifferent", "-passthru",
  ],
}
CMDLET_ALLOWLIST["join-string"] = {
  safeFlags: ["-inputobject", "-separator", "-outputprefix", "-outputsuffix", "-property", "-singlequote", "-doublequote", "-formatstring"],
}
CMDLET_ALLOWLIST["get-random"] = {
  safeFlags: ["-inputobject", "-minimum", "-maximum", "-count", "-setseed", "-shuffle"],
}

// ── Path utilities ──
CMDLET_ALLOWLIST["convert-path"] = {
  safeFlags: ["-path", "-literalpath"],
}
CMDLET_ALLOWLIST["join-path"] = {
  // -Resolve intentionally excluded — it can trigger provider operations
  safeFlags: ["-path", "-childpath", "-additionalchildpath"],
}
CMDLET_ALLOWLIST["split-path"] = {
  // -Resolve intentionally excluded
  safeFlags: ["-path", "-parent", "-leaf", "-leafbase", "-extension", "-qualifier", "-noqualifier", "-isabsolute"],
}

// ── System information ──
CMDLET_ALLOWLIST["get-process"] = {
  safeFlags: ["-name", "-id", "-inputobject", "-includeusername", "-module", "-fileversioninfo"],
}
CMDLET_ALLOWLIST["get-service"] = {
  safeFlags: ["-name", "-displayname", "-include", "-exclude", "-inputobject", "-dependentservices", "-requiredservices"],
}
CMDLET_ALLOWLIST["get-computerinfo"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["get-host"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["get-date"] = {
  safeFlags: ["-date", "-format", "-uformat", "-displayhint", "-asutc", "-year", "-month", "-day", "-hour", "-minute", "-second", "-millisecond"],
}
CMDLET_ALLOWLIST["get-location"] = {
  safeFlags: ["-psdrive", "-psprovider", "-stack", "-stackname"],
}
CMDLET_ALLOWLIST["get-psdrive"] = {
  safeFlags: ["-name", "-psprovider", "-scope", "-literalname"],
}
CMDLET_ALLOWLIST["get-module"] = {
  safeFlags: ["-name", "-fullqualifiedname", "-all", "-listavailable", "-pssnapin", "-psedition"],
}
CMDLET_ALLOWLIST["get-alias"] = {
  safeFlags: ["-name", "-definition", "-exclude", "-scope"],
}
CMDLET_ALLOWLIST["get-history"] = {
  safeFlags: ["-id", "-count"],
}
CMDLET_ALLOWLIST["get-culture"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["get-uiculture"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["get-timezone"] = {
  safeFlags: ["-name", "-id", "-listavailable"],
}
CMDLET_ALLOWLIST["get-uptime"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["get-psprovider"] = {
  safeFlags: ["-psprovider"],
}
CMDLET_ALLOWLIST["get-hotfix"] = {
  safeFlags: ["-id", "-description"],
}

// ── Output (safe — just display) ──
CMDLET_ALLOWLIST["write-output"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["write-host"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["start-sleep"] = {
  safeFlags: ["-seconds", "-milliseconds", "-duration"],
}

// ── Formatting / pipeline (safe — transform/display only) ──
CMDLET_ALLOWLIST["format-table"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["format-list"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["format-wide"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["format-custom"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["measure-object"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["select-object"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["sort-object"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["group-object"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["where-object"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["out-string"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["out-host"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["out-null"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["tee-object"] = { allowAllFlags: true }

// ── Network information (read-only) ──
CMDLET_ALLOWLIST["get-netadapter"] = {
  safeFlags: ["-name", "-interfacedescription", "-interfaceindex", "-includevlan", "-physical"],
}
CMDLET_ALLOWLIST["get-netipaddress"] = {
  safeFlags: ["-addressfamily", "-interfaceindex", "-interfacealias", "-ipaddress", "-prefixlength", "-type"],
}
CMDLET_ALLOWLIST["get-netipconfiguration"] = {
  safeFlags: ["-interfaceindex", "-interfacealias", "-all", "-detailed"],
}
CMDLET_ALLOWLIST["get-netroute"] = {
  safeFlags: ["-addressfamily", "-interfaceindex", "-interfacealias", "-destinationprefix", "-nexthop"],
}
CMDLET_ALLOWLIST["get-dnsclientcache"] = {
  safeFlags: ["-entry", "-data", "-type", "-status", "-section"],
}
CMDLET_ALLOWLIST["get-dnsclient"] = {
  safeFlags: ["-interfaceindex", "-interfacealias"],
}

// ── Event logs (read-only) ──
CMDLET_ALLOWLIST["get-eventlog"] = {
  safeFlags: [
    "-logname", "-newest", "-after", "-before",
    "-username", "-instanceid", "-index",
    "-entrytype", "-source", "-message", "-asbaseobject", "-list", "-asstring",
  ],
}
CMDLET_ALLOWLIST["get-winevent"] = {
  // -FilterXml and -FilterHashtable excluded (XXE risk / complex input)
  safeFlags: [
    "-logname", "-providername", "-listlog", "-listprovider",
    "-maxevents", "-oldest", "-force",
  ],
}

// ── CIM (limited) ──
CMDLET_ALLOWLIST["get-cimclass"] = {
  safeFlags: ["-classname", "-namespace", "-methodname", "-propertyname", "-qualifiername"],
}

// ── External Windows commands ──
CMDLET_ALLOWLIST["ipconfig"] = { safeFlags: ["/all", "/release", "/renew", "/flushdns", "/displaydns", "/allcompartments"] }
CMDLET_ALLOWLIST["netstat"] = { safeFlags: ["-a", "-b", "-e", "-f", "-n", "-o", "-p", "-r", "-s", "-t", "-x", "-y"] }
CMDLET_ALLOWLIST["systeminfo"] = { safeFlags: ["/fo", "/nh"] }
CMDLET_ALLOWLIST["tasklist"] = { safeFlags: ["/fi", "/fo", "/nh", "/v", "/svc", "/apps", "/m"] }
CMDLET_ALLOWLIST["hostname"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["whoami"] = { safeFlags: ["/user", "/groups", "/priv", "/logonid", "/all", "/fo", "/nh", "/upn", "/fqdn"] }
CMDLET_ALLOWLIST["ver"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["arp"] = { safeFlags: ["-a", "-g", "-n"] }
CMDLET_ALLOWLIST["route"] = {
  safeFlags: ["print"],
  isDangerous: (raw: string) => {
    // Only "route print" is safe; "route add/delete/change" are not
    const tokens = raw.trim().split(/\s+/)
    const sub = tokens[1]?.toLowerCase()
    return sub !== undefined && sub !== "print"
  },
}
CMDLET_ALLOWLIST["getmac"] = { safeFlags: ["/fo", "/nh", "/v"] }
CMDLET_ALLOWLIST["where.exe"] = { allowAllFlags: true }
CMDLET_ALLOWLIST["findstr"] = {
  safeFlags: ["/b", "/e", "/l", "/r", "/s", "/i", "/x", "/v", "/n", "/m", "/o", "/p", "/c:", "/g:", "/d:"],
}
CMDLET_ALLOWLIST["tree"] = { safeFlags: ["/f", "/a"] }
CMDLET_ALLOWLIST["file"] = { safeFlags: ["--mime-type", "--brief", "-b", "-i"] }

// ── Git (delegated to specialized validator) ──
CMDLET_ALLOWLIST["git"] = {
  isDangerous: isGitDangerous,
  allowAllFlags: true, // Git safety is fully handled by isDangerous callback
}

// ─── Dangerous Construct Detection ───────────────────────────────────────────

/**
 * Regex patterns for dangerous PowerShell constructs.
 * If any of these match the raw command, it is NOT read-only.
 *
 * These are checked BEFORE cmdlet allowlist lookup.
 */
const DANGEROUS_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  // Sub-expressions: $(...) can execute arbitrary code
  { pattern: /\$\(/, reason: "sub-expression $() detected" },

  // Splatting: @variable passes arbitrary parameters
  // Exclude email-like patterns (user@domain) by requiring word boundary or start
  { pattern: /(?:^|[^\w.])@\w+/, reason: "splatting @variable detected" },

  // Member invocation: .Method() calls arbitrary .NET methods
  { pattern: /\.\w+\s*\(/, reason: "member invocation .Method() detected" },

  // Assignment: $var = ... modifies state
  { pattern: /\$\w+\s*[+\-*/]?=/, reason: "variable assignment detected" },

  // Stop-parsing: --% passes everything literally to native commands
  { pattern: /--\s*%/, reason: "stop-parsing --% detected" },

  // UNC paths: \\server\share can trigger network requests / NTLM leaks
  { pattern: /\\\\/, reason: "UNC path (backslash) detected" },
  { pattern: /(?<!:)\/\//, reason: "UNC path (forward slash) detected" },

  // Static method calls: [Type]::Method() executes arbitrary .NET code
  { pattern: /::/, reason: "static method call :: detected" },

  // Script blocks: { ... } can contain arbitrary code
  { pattern: /\{[^}]*\}/, reason: "script block { } detected" },

  // Backtick command substitution (shouldn't happen in PS, but safety check)
  { pattern: /`[^`]*`/, reason: "backtick substitution detected" },

  // Variable expansion (not in single quotes): $env:, ${...}
  { pattern: /\$env:/i, reason: "$env: environment variable access detected" },
  { pattern: /\$\{/, reason: "${} variable expansion detected" },
]

// ─── Git Validation (for PowerShell) ─────────────────────────────────────────

/**
 * Read-only git subcommands. Matches the bash readonly-commands.ts git validation.
 */
const GIT_READONLY_SUBCOMMANDS = new Set([
  "status", "diff", "log", "show", "blame", "branch", "tag",
  "remote", "ls-files", "stash", "config", "rev-parse",
  "rev-list", "shortlog", "describe", "cat-file", "reflog",
  "ls-tree", "name-rev", "merge-base", "count-objects",
])

/**
 * Git subcommands that need special flag constraints.
 */
const GIT_SUBCOMMAND_CONSTRAINTS: Record<string, { requiredFlags?: string[]; bannedArgs?: RegExp }> = {
  branch: { requiredFlags: ["-a", "-r", "--list", "-l", "-v", "--verbose", "--merged", "--no-merged", "--contains", "--no-contains", "--sort", "--points-at", "--format", "--column", "--no-column"] },
  tag: { requiredFlags: ["-l", "--list", "-n", "--sort", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--format", "--column", "--no-column"] },
  config: { requiredFlags: ["--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin", "--show-scope"] },
  stash: { requiredFlags: ["list", "show"] },
  remote: { requiredFlags: ["-v", "--verbose", "show", "get-url"] },
}

/**
 * Dangerous git global flags that allow code execution.
 */
const GIT_DANGEROUS_FLAGS = new Set([
  "-c", "--exec-path", "--config-env", "--git-dir", "--work-tree", "--attr-source",
])

function isGitDangerous(raw: string): boolean {
  const tokens = tokenize(raw)
  if (tokens.length < 1 || tokens[0]!.toLowerCase() !== "git") return true

  // Check for $ in any token (variable expansion in PowerShell context)
  if (tokens.some(t => t.includes("$"))) return true

  // Skip global flags, reject dangerous ones
  let i = 1
  while (i < tokens.length) {
    const t = tokens[i]!.toLowerCase()
    if (!t.startsWith("-")) break
    // Check for dangerous flags (with or without = value)
    const flagBase = t.split("=")[0]!
    if (GIT_DANGEROUS_FLAGS.has(flagBase)) return true
    // Short flag with attached value: -ccore.pager=sh
    if (t.length > 2 && t.startsWith("-") && !t.startsWith("--") && GIT_DANGEROUS_FLAGS.has(t.slice(0, 2))) return true
    i++
  }

  if (i >= tokens.length) {
    // bare "git" or "git <global-flags>" — safe (just shows help)
    return false
  }

  const subcommand = tokens[i]!.toLowerCase()

  // Not a read-only subcommand
  if (!GIT_READONLY_SUBCOMMANDS.has(subcommand)) return true

  // ls-remote special handling: reject URLs (data exfiltration)
  if (subcommand === "ls-remote") return true // always reject in PowerShell (too complex to validate)

  // Check subcommand-specific constraints
  const constraint = GIT_SUBCOMMAND_CONSTRAINTS[subcommand]
  if (constraint) {
    const remainingArgs = tokens.slice(i + 1)
    const hasRequiredFlag = remainingArgs.some(a => {
      const lower = a.toLowerCase().split("=")[0]!
      return constraint.requiredFlags?.some(f => f.toLowerCase() === lower) ?? false
    })

    // For "branch" and "tag": if there are non-flag args and no read-only flag, it might create a branch/tag
    if (subcommand === "branch" || subcommand === "tag") {
      const nonFlagArgs = remainingArgs.filter(a => !a.startsWith("-"))
      if (nonFlagArgs.length > 0 && !hasRequiredFlag) return true
    }

    // For "config": must have a read flag, otherwise it could set values
    if (subcommand === "config") {
      if (!hasRequiredFlag) return true
    }

    // For "stash": must be "list" or "show"
    if (subcommand === "stash") {
      const sub2 = tokens[i + 1]?.toLowerCase()
      if (sub2 !== "list" && sub2 !== "show" && sub2 !== undefined) return true
      // bare "git stash" creates a stash — dangerous
      if (sub2 === undefined) return true
    }

    // For "remote": must be bare, -v, "show", or "get-url"
    if (subcommand === "remote") {
      const sub2 = tokens[i + 1]?.toLowerCase()
      if (sub2 === "add" || sub2 === "remove" || sub2 === "rename" || sub2 === "set-url" || sub2 === "set-head" || sub2 === "prune") return true
    }
  }

  return false
}

// ─── Tokenizer ───────────────────────────────────────────────────────────────

/**
 * Simple PowerShell command tokenizer.
 * Handles single-quoted strings, double-quoted strings, and whitespace splitting.
 * Does NOT handle all PowerShell edge cases (by design — fails closed).
 */
function tokenize(command: string): string[] {
  const tokens: string[] = []
  let current = ""
  let inSingle = false
  let inDouble = false
  let i = 0

  while (i < command.length) {
    const ch = command[i]!

    if (inSingle) {
      if (ch === "'") {
        // PowerShell: '' inside single quotes is an escaped quote
        if (i + 1 < command.length && command[i + 1] === "'") {
          current += "'"
          i += 2
          continue
        }
        inSingle = false
      } else {
        current += ch
      }
      i++
      continue
    }

    if (inDouble) {
      if (ch === '"') {
        inDouble = false
      } else if (ch === "`" && i + 1 < command.length) {
        // PowerShell escape character inside double quotes
        current += command[i + 1]
        i += 2
        continue
      } else {
        current += ch
      }
      i++
      continue
    }

    // Outside quotes
    if (ch === "'") {
      inSingle = true
      i++
      continue
    }
    if (ch === '"') {
      inDouble = true
      i++
      continue
    }
    if (ch === " " || ch === "\t") {
      if (current.length > 0) {
        tokens.push(current)
        current = ""
      }
      i++
      continue
    }

    current += ch
    i++
  }

  if (current.length > 0) {
    tokens.push(current)
  }

  return tokens
}

// ─── Command Splitting ──────────────────────────────────────────────────────

/**
 * Split compound PowerShell command into sub-commands.
 * Splits on: ; (statement separator), | (pipe)
 *
 * Does NOT split on && or || — PowerShell 5.1 doesn't support them,
 * and PowerShell 7+ does but we reject them as unusual for read-only use.
 */
function splitCompound(command: string): string[] {
  const parts: string[] = []
  let current = ""
  let inSingle = false
  let inDouble = false
  let i = 0

  while (i < command.length) {
    const ch = command[i]!

    if (inSingle) {
      current += ch
      if (ch === "'") {
        if (i + 1 < command.length && command[i + 1] === "'") {
          current += "'"
          i += 2
          continue
        }
        inSingle = false
      }
      i++
      continue
    }

    if (inDouble) {
      current += ch
      if (ch === '"') {
        inDouble = false
      } else if (ch === "`" && i + 1 < command.length) {
        current += command[i + 1]
        i += 2
        continue
      }
      i++
      continue
    }

    if (ch === "'") {
      inSingle = true
      current += ch
      i++
      continue
    }
    if (ch === '"') {
      inDouble = true
      current += ch
      i++
      continue
    }

    // Split on ; or |
    if (ch === ";" || ch === "|") {
      const trimmed = current.trim()
      if (trimmed.length > 0) parts.push(trimmed)
      current = ""
      i++
      continue
    }

    // Reject && and || (PS7 operators — too complex for simple validation)
    if ((ch === "&" && i + 1 < command.length && command[i + 1] === "&") ||
        (ch === "|" && i + 1 < command.length && command[i + 1] === "|")) {
      // Return the whole command as one part — it will fail validation
      return [command.trim()]
    }

    current += ch
    i++
  }

  const trimmed = current.trim()
  if (trimmed.length > 0) parts.push(trimmed)

  return parts
}

// ─── Resolve Alias ──────────────────────────────────────────────────────────

/**
 * Resolve a command name to its canonical cmdlet name.
 * Strips .exe/.cmd/.bat/.com suffixes (for external commands),
 * then checks the alias table.
 */
function resolveToCanonical(name: string): string {
  let lower = name.toLowerCase()

  // Only strip PATHEXT for bare names (not paths)
  if (!lower.includes("\\") && !lower.includes("/")) {
    lower = lower.replace(/\.(exe|cmd|bat|com)$/, "")
  }

  const alias = ALIASES[lower]
  if (alias) return alias

  return lower
}

// ─── CWD-Changing Cmdlets ────────────────────────────────────────────────────

const CWD_CMDLETS = new Set([
  "set-location", "push-location", "pop-location",
])

// ─── Main Entry Point ────────────────────────────────────────────────────────

/**
 * Check if a PowerShell command is read-only and safe for auto-approval.
 *
 * @param command The raw PowerShell command string
 * @returns { readonly: true } if safe, { readonly: false, reason: string } if not
 */
export function isReadOnlyPowerShellCommand(command: string): ReadOnlyResult {
  const trimmed = command.trim()
  if (trimmed.length === 0) {
    return { readonly: false, reason: "empty command" }
  }

  // ── Step 1: Check for dangerous PowerShell constructs ──
  for (const { pattern, reason } of DANGEROUS_PATTERNS) {
    // Check against command with single-quoted content removed
    // Single quotes in PowerShell are literal — no expansion inside them
    const withoutSingleQuoted = trimmed.replace(/'[^']*'/g, "''")
    if (pattern.test(withoutSingleQuoted)) {
      return { readonly: false, reason }
    }
  }

  // ── Step 2: Check for && / || operators (PS7) ──
  // Strip quoted content first, then check
  const unquoted = trimmed.replace(/'[^']*'/g, "").replace(/"[^"]*"/g, "")
  if (/&&/.test(unquoted) || /\|\|/.test(unquoted)) {
    return { readonly: false, reason: "pipeline chain operator (&& or ||) detected" }
  }

  // ── Step 3: Split compound command ──
  const subCommands = splitCompound(trimmed)
  if (subCommands.length === 0) {
    return { readonly: false, reason: "no commands found" }
  }

  // ── Step 4: CWD-change + other commands check ──
  // If a compound command changes CWD and then runs another command,
  // the path context is different from what we validated — reject.
  if (subCommands.length > 1) {
    for (const sub of subCommands) {
      const firstToken = tokenize(sub)[0]
      if (firstToken) {
        const canonical = resolveToCanonical(firstToken)
        if (CWD_CMDLETS.has(canonical)) {
          return { readonly: false, reason: "CWD-changing cmdlet in compound command (sandbox escape risk)" }
        }
      }
    }
  }

  // ── Step 5: Validate each sub-command ──
  for (const sub of subCommands) {
    const result = validateSingleCommand(sub)
    if (!result.readonly) return result
  }

  return { readonly: true }
}

// ─── Single Command Validation ───────────────────────────────────────────────

function validateSingleCommand(command: string): ReadOnlyResult {
  const tokens = tokenize(command)
  if (tokens.length === 0) {
    return { readonly: false, reason: "empty sub-command" }
  }

  const rawName = tokens[0]!
  const canonical = resolveToCanonical(rawName)

  // Look up in allowlist
  const config = CMDLET_ALLOWLIST[canonical]
  if (!config) {
    return { readonly: false, reason: `command '${rawName}' not in read-only allowlist` }
  }

  // Custom danger check
  if (config.isDangerous && config.isDangerous(command)) {
    return { readonly: false, reason: `command '${rawName}' flagged as dangerous by custom check` }
  }

  // Flag validation
  if (config.allowAllFlags) {
    return { readonly: true }
  }

  // Validate flags
  const safeFlagSet = new Set(config.safeFlags?.map(f => f.toLowerCase()) ?? [])
  const isCmdlet = canonical.includes("-")

  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i]!

    // Detect PowerShell flags
    let isFlag = false
    let flagName = ""

    if (isCmdlet) {
      // Cmdlet flags: -FlagName or -FlagName:value
      // PowerShell also uses Unicode hyphens sometimes
      if (token.startsWith("-") || token.startsWith("\u2013") || token.startsWith("\u2014")) {
        isFlag = true
        // Normalize: strip Unicode hyphens to ASCII
        flagName = "-" + token.slice(1)
        // Remove :value suffix
        const colonIdx = flagName.indexOf(":")
        if (colonIdx > 0) flagName = flagName.slice(0, colonIdx)
        flagName = flagName.toLowerCase()
      }
    } else {
      // External command flags: -flag or /flag (Windows)
      if (token.startsWith("-") || token.startsWith("/")) {
        isFlag = true
        flagName = token.toLowerCase()
        // Remove =value suffix
        const eqIdx = flagName.indexOf("=")
        if (eqIdx > 0) flagName = flagName.slice(0, eqIdx)
        // Remove :value suffix
        const colonIdx = flagName.indexOf(":")
        if (colonIdx > 0) flagName = flagName.slice(0, colonIdx)

        // Combined short flags: -an → check -a and -n individually
        // Only for dash-prefixed flags (not /flag) that are > 2 chars and not --long
        if (flagName.startsWith("-") && !flagName.startsWith("--") && flagName.length > 2) {
          // Try to validate each character as a separate flag
          let allValid = true
          for (let c = 1; c < flagName.length; c++) {
            const singleFlag = "-" + flagName[c]
            if (!safeFlagSet.has(singleFlag)) {
              allValid = false
              break
            }
          }
          if (allValid) continue // All individual flags are safe
          // If not all valid as combined, fall through to normal check
        }
      }
    }

    if (!isFlag) continue // Positional argument — allowed by default

    // Common parameters are always safe for cmdlets
    if (isCmdlet && COMMON_PARAMETERS.has(flagName)) continue

    // Check against safe flags
    if (safeFlagSet.size === 0) {
      // No safe flags defined = no flags allowed
      return { readonly: false, reason: `flag '${token}' not allowed for '${rawName}' (no flags defined)` }
    }

    if (!safeFlagSet.has(flagName)) {
      return { readonly: false, reason: `flag '${token}' not in safe list for '${rawName}'` }
    }
  }

  return { readonly: true }
}
