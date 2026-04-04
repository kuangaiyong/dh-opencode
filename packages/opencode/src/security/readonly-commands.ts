/**
 * Read-Only Command Auto-Approval Engine
 *
 * Ported from Claude Code's readOnlyValidation.ts (~1990 lines) and
 * readOnlyCommandValidation.ts (~1893 lines). This is a simplified but
 * security-conscious implementation that auto-approves bash commands which
 * are purely read-only (no file writes, no code execution, no network requests).
 *
 * Design decisions:
 * - Uses regex-based command matching (no shell-quote parser dependency)
 * - Fails closed: any ambiguity → NOT read-only → user prompt
 * - Compound commands (pipes, &&, ;, ||) are split and each sub-command checked
 * - Variable expansion ($VAR), command substitution ($(), ``), globs (*, ?, [])
 *   outside quotes → NOT read-only (runtime value unknown)
 * - Flag validation for high-risk commands (git, find, etc.) via explicit safe-flag sets
 *
 * Reference: CC tools/BashTool/readOnlyValidation.ts
 *            CC utils/shell/readOnlyCommandValidation.ts
 */

// ─── Types ───────────────────────────────────────────────────────────────────

type FlagArgType =
  | "none" // Boolean flag, no argument (--color, -n)
  | "number" // Integer argument (--context=3)
  | "string" // Any string argument (--relative=path)

type CommandConfig = {
  /** Map of safe flags → expected argument type */
  safeFlags: Record<string, FlagArgType>
  /** If true, command allows positional args after flags (default: true) */
  allowPositionalArgs?: boolean
  /** Custom danger check: returns true if command looks dangerous */
  isDangerous?: (raw: string, args: string[]) => boolean
}

export type ReadOnlyResult = {
  readonly: boolean
  reason?: string
}

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * Simple read-only commands that are safe with any non-shell-meta arguments.
 * These commands have NO flags that can write files, execute code, or make
 * network requests.
 *
 * Reference: CC READONLY_COMMANDS array + makeRegexForSafeCommand()
 */
const SIMPLE_READONLY_COMMANDS = new Set([
  // File content viewing
  "cat",
  "head",
  "tail",
  "wc",
  "stat",
  "strings",
  "hexdump",
  "od",
  "nl",
  "tac",
  "rev",
  // Path information
  "basename",
  "dirname",
  "realpath",
  "readlink",
  // Text processing (read-only)
  "cut",
  "paste",
  "tr",
  "column",
  "fold",
  "expand",
  "unexpand",
  "fmt",
  "comm",
  "cmp",
  "numfmt",
  // File comparison
  "diff",
  // System info
  "id",
  "uname",
  "free",
  "df",
  "du",
  "locale",
  "groups",
  "nproc",
  // Time and date
  "cal",
  "uptime",
  "date",
  "hostname",
  // Misc safe
  "sleep",
  "which",
  "type",
  "expr",
  "test",
  "getconf",
  "seq",
  "tsort",
  "pr",
  "true",
  "false",
])

/**
 * Commands that require exact regex matching (no arbitrary suffixes).
 *
 * Reference: CC READONLY_COMMAND_REGEXES
 */
const EXACT_MATCH_REGEXES: Array<{ pattern: RegExp; description: string }> = [
  // echo: safe if no variable expansion, command substitution, or shell metacharacters
  // Allow newlines in single quotes but not in double quotes
  {
    pattern: /^echo(?:\s+(?:'[^']*'|"[^"$<>\n\r]*"|[^|;&`$(){}><#\\!"'\s]+))*(?:\s+2>&1)?\s*$/,
    description: "echo with safe arguments",
  },
  // uniq: only allow flags, no input/output files (output files enable file writes)
  {
    pattern: /^uniq(?:\s+(?:-[a-zA-Z]+|--[a-zA-Z-]+(?:=\S+)?|-[fsw]\s+\d+))*(?:\s|$)\s*$/,
    description: "uniq with flags only",
  },
  // pwd, whoami: exact match only
  { pattern: /^pwd$/, description: "pwd" },
  { pattern: /^whoami$/, description: "whoami" },
  // Version checking: exact match, no suffix allowed
  // SECURITY: `node -v --run <task>` executes package.json scripts
  { pattern: /^node -v$/, description: "node version" },
  { pattern: /^node --version$/, description: "node version" },
  { pattern: /^python --version$/, description: "python version" },
  { pattern: /^python3 --version$/, description: "python3 version" },
  // history: only bare or with numeric argument
  { pattern: /^history(?:\s+\d+)?\s*$/, description: "history" },
  // alias: bare only
  { pattern: /^alias$/, description: "alias" },
  // arch: only with help flags or no arguments
  { pattern: /^arch(?:\s+(?:--help|-h))?\s*$/, description: "arch" },
  // Network info: very restricted
  { pattern: /^ip addr$/, description: "ip addr" },
  { pattern: /^ifconfig(?:\s+[a-zA-Z][a-zA-Z0-9_-]*)?\s*$/, description: "ifconfig" },
  // ls: safe with non-shell-meta arguments
  { pattern: /^ls(?:\s+[^<>()$`|{}&;\n\r]*)?$/, description: "ls" },
  // find: safe except for dangerous action flags
  {
    pattern:
      /^find(?:\s+(?:\\[()]|(?!-delete\b|-exec\b|-execdir\b|-ok\b|-okdir\b|-fprint0?\b|-fls\b|-fprintf\b)[^<>()$`|{}&;\n\r\s]|\s)+)?$/,
    description: "find without dangerous flags",
  },
  // cd: change directory (no side effects)
  { pattern: /^cd(?:\s+(?:'[^']*'|"[^"]*"|[^\s;|&`$(){}><#\\]+))?$/, description: "cd" },
  // jq: safe if no dangerous flags (-f, --from-file, --rawfile, --slurpfile, --run-tests, -L, --library-path, env, $ENV)
  {
    pattern:
      /^jq(?!\s+.*(?:-f\b|--from-file|--rawfile|--slurpfile|--run-tests|-L\b|--library-path|\benv\b|\$ENV\b))(?:\s+(?:-[a-zA-Z]+|--[a-zA-Z-]+(?:=\S+)?))*(?:\s+'[^'`]*'|\s+"[^"`]*"|\s+[^-\s'"][^\s]*)+\s*$/,
    description: "jq with safe flags",
  },
]

/**
 * Commands that use flag-based validation via COMMAND_ALLOWLIST.
 * Each entry defines safe flags and their argument types.
 * Flags NOT in the list → command is NOT read-only.
 *
 * Reference: CC COMMAND_ALLOWLIST + GIT_READ_ONLY_COMMANDS
 */
const COMMAND_ALLOWLIST: Record<string, CommandConfig> = {
  // ── Git read-only commands ──

  "git status": {
    safeFlags: {
      "--short": "none",
      "-s": "none",
      "--branch": "none",
      "-b": "none",
      "--porcelain": "none",
      "--long": "none",
      "--verbose": "none",
      "-v": "none",
      "--untracked-files": "string",
      "-u": "string",
      "--ignored": "none",
      "--ignore-submodules": "string",
      "--column": "string",
      "--no-column": "none",
      "--ahead-behind": "none",
      "--no-ahead-behind": "none",
      "--renames": "none",
      "--no-renames": "none",
    },
  },
  "git diff": {
    safeFlags: {
      "--stat": "none",
      "--numstat": "none",
      "--shortstat": "none",
      "--name-only": "none",
      "--name-status": "none",
      "--color": "none",
      "--no-color": "none",
      "--patch": "none",
      "-p": "none",
      "-u": "none",
      "--no-patch": "none",
      "-s": "none",
      "--no-ext-diff": "none",
      "--cached": "none",
      "--staged": "none",
      "--word-diff": "none",
      "--color-words": "none",
      "--no-renames": "none",
      "--check": "none",
      "--full-index": "none",
      "--binary": "none",
      "--abbrev": "number",
      "--diff-algorithm": "string",
      "--histogram": "none",
      "--patience": "none",
      "--minimal": "none",
      "--ignore-space-at-eol": "none",
      "--ignore-space-change": "none",
      "--ignore-all-space": "none",
      "--ignore-blank-lines": "none",
      "--inter-hunk-context": "number",
      "--function-context": "none",
      "--exit-code": "none",
      "--quiet": "none",
      "--no-index": "none",
      "--relative": "string",
      "--diff-filter": "string",
      "--dirstat": "none",
      "--summary": "none",
      "-M": "none",
      "-C": "none",
      "-B": "none",
      "-D": "none",
      "-R": "none",
      "-S": "string",
      "-G": "string",
      "-O": "string",
    },
  },
  "git log": {
    safeFlags: {
      "--oneline": "none",
      "--graph": "none",
      "--decorate": "none",
      "--no-decorate": "none",
      "--date": "string",
      "--relative-date": "none",
      "--all": "none",
      "--branches": "none",
      "--tags": "none",
      "--remotes": "none",
      "--since": "string",
      "--after": "string",
      "--until": "string",
      "--before": "string",
      "--max-count": "number",
      "-n": "number",
      "--stat": "none",
      "--numstat": "none",
      "--shortstat": "none",
      "--name-only": "none",
      "--name-status": "none",
      "--color": "none",
      "--no-color": "none",
      "--patch": "none",
      "-p": "none",
      "--no-patch": "none",
      "--no-ext-diff": "none",
      "-s": "none",
      "--author": "string",
      "--committer": "string",
      "--grep": "string",
      "--abbrev-commit": "none",
      "--full-history": "none",
      "--first-parent": "none",
      "--merges": "none",
      "--no-merges": "none",
      "--reverse": "none",
      "--walk-reflogs": "none",
      "--skip": "number",
      "--format": "string",
      "--pretty": "string",
      "--topo-order": "none",
      "--date-order": "none",
      "--author-date-order": "none",
      "--diff-filter": "string",
      "--follow": "none",
      "--left-right": "none",
      "--cherry-pick": "none",
      "--cherry-mark": "none",
      "--ancestry-path": "none",
      "--simplify-merges": "none",
      "--source": "none",
    },
  },
  "git show": {
    safeFlags: {
      "--stat": "none",
      "--numstat": "none",
      "--shortstat": "none",
      "--name-only": "none",
      "--name-status": "none",
      "--color": "none",
      "--no-color": "none",
      "--patch": "none",
      "-p": "none",
      "--no-patch": "none",
      "--no-ext-diff": "none",
      "-s": "none",
      "--format": "string",
      "--pretty": "string",
      "--abbrev-commit": "none",
      "--oneline": "none",
      "--diff-filter": "string",
      "--word-diff": "none",
    },
  },
  "git blame": {
    safeFlags: {
      "-L": "string",
      "--since": "string",
      "-w": "none",
      "--show-email": "none",
      "-e": "none",
      "--show-name": "none",
      "-f": "none",
      "--show-number": "none",
      "-n": "none",
      "--porcelain": "none",
      "--line-porcelain": "none",
      "-p": "none",
      "--color-lines": "none",
      "--color-by-age": "none",
      "--date": "string",
      "--root": "none",
      "-t": "none",
      "--abbrev": "number",
    },
  },
  "git branch": {
    safeFlags: {
      "--list": "none",
      "-l": "none",
      "--all": "none",
      "-a": "none",
      "--remotes": "none",
      "-r": "none",
      "--verbose": "none",
      "-v": "none",
      "-vv": "none",
      "--merged": "string",
      "--no-merged": "string",
      "--contains": "string",
      "--no-contains": "string",
      "--sort": "string",
      "--format": "string",
      "--color": "none",
      "--no-color": "none",
      "--column": "string",
      "--no-column": "none",
      "--abbrev": "number",
      "--no-abbrev": "none",
    },
    isDangerous: (_raw: string, args: string[]) => {
      // git branch with positional args (besides pattern for --list) could create/delete branches
      // If there's a positional arg that doesn't look like a branch filter pattern, reject
      // Allow args that look like refs (for --contains, --merged, etc. which are already covered by flags)
      // SECURITY: git branch <name> creates a branch. Reject if no --list flag and has positional args
      const hasListFlag = args.some((a) => a === "--list" || a === "-l" || a === "-a" || a === "--all" || a === "-r" || a === "--remotes")
      if (!hasListFlag && args.some((a) => !a.startsWith("-"))) {
        return true
      }
      return false
    },
  },
  "git tag": {
    safeFlags: {
      "--list": "none",
      "-l": "none",
      "--sort": "string",
      "--format": "string",
      "--merged": "string",
      "--no-merged": "string",
      "--contains": "string",
      "--no-contains": "string",
      "--color": "none",
      "--no-color": "none",
      "--column": "string",
      "--no-column": "none",
      "-n": "number",
    },
    isDangerous: (_raw: string, args: string[]) => {
      // git tag without --list could create a tag
      const hasListFlag = args.some((a) => a === "--list" || a === "-l")
      if (!hasListFlag && args.some((a) => !a.startsWith("-"))) {
        return true
      }
      return false
    },
  },
  "git remote": {
    safeFlags: {
      "--verbose": "none",
      "-v": "none",
    },
    isDangerous: (raw: string) => {
      // Only allow: git remote, git remote -v, git remote show <name>, git remote get-url <name>
      const trimmed = raw.trim()
      if (/^git\s+remote\s*$/.test(trimmed)) return false
      if (/^git\s+remote\s+(-v|--verbose)\s*$/.test(trimmed)) return false
      if (/^git\s+remote\s+show\s+\S+\s*$/.test(trimmed)) return false
      if (/^git\s+remote\s+get-url\s+\S+\s*$/.test(trimmed)) return false
      return true // anything else (add, remove, rename, set-url) is dangerous
    },
  },
  "git ls-files": {
    safeFlags: {
      "--cached": "none",
      "-c": "none",
      "--deleted": "none",
      "-d": "none",
      "--modified": "none",
      "-m": "none",
      "--others": "none",
      "-o": "none",
      "--ignored": "none",
      "-i": "none",
      "--stage": "none",
      "-s": "none",
      "--unmerged": "none",
      "-u": "none",
      "--killed": "none",
      "-k": "none",
      "--full-name": "none",
      "--error-unmatch": "none",
      "--exclude": "string",
      "-x": "string",
      "--exclude-from": "string",
      "-X": "string",
      "--exclude-per-directory": "string",
      "--exclude-standard": "none",
      "-z": "none",
      "--debug": "none",
      "--deduplicate": "none",
    },
  },
  "git stash list": {
    safeFlags: {
      "--oneline": "none",
      "--format": "string",
      "--pretty": "string",
      "--date": "string",
      "--stat": "none",
      "--no-patch": "none",
      "-p": "none",
      "--patch": "none",
    },
  },
  "git stash show": {
    safeFlags: {
      "--stat": "none",
      "--no-patch": "none",
      "-p": "none",
      "--patch": "none",
      "--name-only": "none",
      "--name-status": "none",
      "--numstat": "none",
      "--shortstat": "none",
      "--color": "none",
      "--no-color": "none",
    },
  },
  "git config": {
    safeFlags: {
      "--get": "none",
      "--get-all": "none",
      "--list": "none",
      "-l": "none",
      "--local": "none",
      "--global": "none",
      "--system": "none",
      "--show-origin": "none",
      "--show-scope": "none",
      "--name-only": "none",
      "-z": "none",
    },
    isDangerous: (raw: string) => {
      // Only allow read operations: --get, --get-all, --list
      const trimmed = raw.trim()
      if (/\s--(?:get|get-all|list)\b/.test(trimmed) || /\s-l\b/.test(trimmed)) return false
      return true
    },
  },
  "git ls-remote": {
    safeFlags: {
      "--heads": "none",
      "--tags": "none",
      "--refs": "none",
      "--quiet": "none",
      "-q": "none",
      "--exit-code": "none",
      "--get-url": "none",
      "--sort": "string",
    },
    isDangerous: (_raw: string, args: string[]) => {
      // Reject URLs that could exfiltrate data
      for (const arg of args) {
        if (arg.startsWith("-")) continue
        if (arg.includes("://") || arg.includes("@") || arg.includes(":") || arg.includes("$")) {
          return true
        }
      }
      return false
    },
  },
  "git rev-parse": {
    safeFlags: {
      "--abbrev-ref": "none",
      "--short": "none",
      "--verify": "none",
      "--symbolic-full-name": "none",
      "--symbolic": "none",
      "--show-toplevel": "none",
      "--show-cdup": "none",
      "--show-prefix": "none",
      "--git-dir": "none",
      "--git-common-dir": "none",
      "--is-inside-work-tree": "none",
      "--is-inside-git-dir": "none",
      "--is-bare-repository": "none",
      "--resolve-git-dir": "string",
      "--absolute-git-dir": "none",
      "--show-superproject-working-tree": "none",
      "--all": "none",
      "--branches": "none",
      "--tags": "none",
      "--remotes": "none",
    },
  },
  "git rev-list": {
    safeFlags: {
      "--count": "none",
      "--max-count": "number",
      "-n": "number",
      "--all": "none",
      "--branches": "none",
      "--tags": "none",
      "--remotes": "none",
      "--since": "string",
      "--after": "string",
      "--until": "string",
      "--before": "string",
      "--author": "string",
      "--committer": "string",
      "--grep": "string",
      "--first-parent": "none",
      "--merges": "none",
      "--no-merges": "none",
      "--topo-order": "none",
      "--date-order": "none",
      "--reverse": "none",
      "--ancestry-path": "none",
      "--left-right": "none",
      "--cherry-pick": "none",
      "--cherry-mark": "none",
      "--oneline": "none",
      "--format": "string",
      "--abbrev-commit": "none",
    },
  },
  "git shortlog": {
    safeFlags: {
      "-s": "none",
      "-n": "none",
      "-e": "none",
      "--summary": "none",
      "--numbered": "none",
      "--email": "none",
      "--group": "string",
      "--format": "string",
      "--all": "none",
    },
  },
  "git describe": {
    safeFlags: {
      "--tags": "none",
      "--all": "none",
      "--long": "none",
      "--abbrev": "number",
      "--candidates": "number",
      "--always": "none",
      "--first-parent": "none",
      "--match": "string",
      "--exclude": "string",
      "--contains": "none",
      "--dirty": "none",
      "--broken": "none",
    },
  },
  "git cat-file": {
    safeFlags: {
      "-t": "none",
      "-s": "none",
      "-e": "none",
      "-p": "none",
      "--textconv": "none",
      "--batch": "none",
      "--batch-check": "none",
      "--batch-all-objects": "none",
    },
  },
  "git reflog": {
    safeFlags: {
      "--all": "none",
      "--oneline": "none",
      "--format": "string",
      "--date": "string",
      "-n": "number",
      "--max-count": "number",
    },
  },

  // ── Non-git commands with flag validation ──

  grep: {
    safeFlags: {
      "-i": "none",
      "--ignore-case": "none",
      "-v": "none",
      "--invert-match": "none",
      "-c": "none",
      "--count": "none",
      "-l": "none",
      "--files-with-matches": "none",
      "-L": "none",
      "--files-without-match": "none",
      "-n": "none",
      "--line-number": "none",
      "-H": "none",
      "--with-filename": "none",
      "-h": "none",
      "--no-filename": "none",
      "-o": "none",
      "--only-matching": "none",
      "-w": "none",
      "--word-regexp": "none",
      "-x": "none",
      "--line-regexp": "none",
      "-E": "none",
      "--extended-regexp": "none",
      "-F": "none",
      "--fixed-strings": "none",
      "-P": "none",
      "--perl-regexp": "none",
      "-r": "none",
      "-R": "none",
      "--recursive": "none",
      "-q": "none",
      "--quiet": "none",
      "--silent": "none",
      "-s": "none",
      "--no-messages": "none",
      "--color": "string",
      "--colour": "string",
      "-m": "number",
      "--max-count": "number",
      "-A": "number",
      "--after-context": "number",
      "-B": "number",
      "--before-context": "number",
      "-C": "number",
      "--context": "number",
      "-e": "string",
      "--regexp": "string",
      "--include": "string",
      "--exclude": "string",
      "--exclude-dir": "string",
      "-f": "string",
      "--file": "string",
      "--label": "string",
      "--binary-files": "string",
      "-T": "none",
      "--initial-tab": "none",
      "-Z": "none",
      "--null": "none",
      "-a": "none",
      "--text": "none",
    },
  },
  rg: {
    safeFlags: {
      "-i": "none",
      "--ignore-case": "none",
      "-S": "none",
      "--smart-case": "none",
      "-v": "none",
      "--invert-match": "none",
      "-c": "none",
      "--count": "none",
      "-l": "none",
      "--files-with-matches": "none",
      "--files-without-match": "none",
      "-n": "none",
      "--line-number": "none",
      "-N": "none",
      "--no-line-number": "none",
      "-H": "none",
      "--with-filename": "none",
      "--no-filename": "none",
      "-o": "none",
      "--only-matching": "none",
      "-w": "none",
      "--word-regexp": "none",
      "-x": "none",
      "--line-regexp": "none",
      "-F": "none",
      "--fixed-strings": "none",
      "-U": "none",
      "--multiline": "none",
      "-P": "none",
      "--pcre2": "none",
      "-r": "string",
      "--replace": "string",
      "-e": "string",
      "--regexp": "string",
      "-g": "string",
      "--glob": "string",
      "--iglob": "string",
      "-t": "string",
      "--type": "string",
      "-T": "string",
      "--type-not": "string",
      "-m": "number",
      "--max-count": "number",
      "--max-depth": "number",
      "--maxdepth": "number",
      "-A": "number",
      "--after-context": "number",
      "-B": "number",
      "--before-context": "number",
      "-C": "number",
      "--context": "number",
      "--color": "string",
      "--colours": "string",
      "--column": "none",
      "--no-column": "none",
      "--hidden": "none",
      "--no-ignore": "none",
      "--no-ignore-vcs": "none",
      "--no-heading": "none",
      "--heading": "none",
      "-p": "none",
      "--pretty": "none",
      "--sort": "string",
      "--sortr": "string",
      "-j": "number",
      "--threads": "number",
      "-0": "none",
      "--null": "none",
      "--json": "none",
      "--stats": "none",
      "--trim": "none",
      "-L": "none",
      "--follow": "none",
      "--one-file-system": "none",
      "--no-unicode": "none",
      "--crlf": "none",
      "--mmap": "none",
      "--no-mmap": "none",
      "--binary": "none",
      "--no-binary": "none",
      "--text": "none",
      "-a": "none",
      "--files": "none",
      "--type-list": "none",
      "--debug": "none",
      "-q": "none",
      "--quiet": "none",
    },
  },
  tree: {
    safeFlags: {
      "-a": "none",
      "-d": "none",
      "-l": "none",
      "-f": "none",
      "-i": "none",
      "-q": "none",
      "-N": "none",
      "-Q": "none",
      "-p": "none",
      "-u": "none",
      "-g": "none",
      "-s": "none",
      "-h": "none",
      "-D": "none",
      "--inodes": "none",
      "--device": "none",
      "-F": "none",
      "-n": "none",
      "-C": "none",
      "--noreport": "none",
      "--dirsfirst": "none",
      "--filelimit": "number",
      "-L": "number",
      "-I": "string",
      "-P": "string",
      "--charset": "string",
      "--du": "none",
      "--si": "none",
      "--prune": "none",
      "--timefmt": "string",
      "-t": "none",
      "-r": "none",
      "-v": "none",
      "-U": "none",
      "-c": "none",
      "--sort": "string",
      "-J": "none",
      "-X": "none",
      "-H": "string",
      // SECURITY: -o/--output EXCLUDED — writes output to file
    },
  },
  sort: {
    safeFlags: {
      "-b": "none",
      "--ignore-leading-blanks": "none",
      "-d": "none",
      "--dictionary-order": "none",
      "-f": "none",
      "--ignore-case": "none",
      "-g": "none",
      "--general-numeric-sort": "none",
      "-h": "none",
      "--human-numeric-sort": "none",
      "-i": "none",
      "--ignore-nonprinting": "none",
      "-M": "none",
      "--month-sort": "none",
      "-n": "none",
      "--numeric-sort": "none",
      "-R": "none",
      "--random-sort": "none",
      "-r": "none",
      "--reverse": "none",
      "--sort": "string",
      "-s": "none",
      "--stable": "none",
      "-u": "none",
      "--unique": "none",
      "-V": "none",
      "--version-sort": "none",
      "-z": "none",
      "--zero-terminated": "none",
      "-k": "string",
      "--key": "string",
      "-t": "string",
      "--field-separator": "string",
      "-c": "none",
      "--check": "none",
      "-C": "none",
      "--check-char-order": "none",
      "-m": "none",
      "--merge": "none",
      "-S": "string",
      "--buffer-size": "string",
      "--parallel": "number",
      "--batch-size": "number",
      "--help": "none",
      "--version": "none",
    },
  },
  file: {
    safeFlags: {
      "--brief": "none",
      "-b": "none",
      "--mime": "none",
      "-i": "none",
      "--mime-type": "none",
      "--mime-encoding": "none",
      "-c": "none",
      "--exclude": "string",
      "--print0": "none",
      "-0": "none",
      "-f": "string",
      "-F": "string",
      "--separator": "string",
      "--help": "none",
      "--version": "none",
      "-v": "none",
      "--no-dereference": "none",
      "-h": "none",
      "--dereference": "none",
      "-L": "none",
      "--magic-file": "string",
      "-m": "string",
      "--keep-going": "none",
      "-k": "none",
      "--list": "none",
      "-l": "none",
      "--no-buffer": "none",
      "-n": "none",
      "--preserve-date": "none",
      "-p": "none",
      "--raw": "none",
      "-r": "none",
      "-s": "none",
      "--special-files": "none",
      "--uncompress": "none",
      "-z": "none",
    },
  },
}

// ─── Utility Functions ───────────────────────────────────────────────────────

/**
 * Check if the raw command string contains unquoted shell expansions that
 * make it impossible to determine read-only status at static analysis time.
 *
 * We check for:
 * - Variable expansion: $VAR, ${VAR}, $(), ``
 * - Glob characters: *, ?, [] (outside quotes)
 *
 * Reference: CC containsUnquotedExpansion()
 */
function containsUnsafeExpansion(command: string): boolean {
  let inSingleQuote = false
  let inDoubleQuote = false
  let escaped = false

  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!

    if (escaped) {
      escaped = false
      continue
    }

    // SECURITY: Backslash is literal inside single quotes in bash
    if (ch === "\\" && !inSingleQuote) {
      escaped = true
      continue
    }

    if (ch === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote
      continue
    }

    if (ch === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote
      continue
    }

    // Inside single quotes: everything is literal
    if (inSingleQuote) continue

    // $ expands inside double quotes AND unquoted
    if (ch === "$") {
      const next = command[i + 1]
      if (next && /[A-Za-z_@*#?!$0-9({-]/.test(next)) {
        return true
      }
    }

    // Backtick command substitution
    if (ch === "`") return true

    // Globs: only outside ALL quotes
    if (!inDoubleQuote && /[?*[\]]/.test(ch)) {
      return true
    }
  }

  return false
}

/**
 * Check for Windows UNC paths that could trigger WebDAV/SMB credential theft.
 *
 * Reference: CC containsVulnerableUncPath()
 */
function containsUncPath(command: string): boolean {
  // Match \\server\share or //server/share patterns
  return /(?:^|\s)(?:\\\\|\/\/)[^\s\\/]+[/\\]/.test(command)
}

/**
 * Split a compound command into sub-commands by shell operators.
 * Handles: | (pipe), && (and), || (or), ; (semicolon)
 * Respects quotes and escapes.
 *
 * This is a simplified version — it does not handle all edge cases
 * (e.g., nested subshells), but for those cases containsUnsafeExpansion
 * would have already rejected the command.
 */
function splitSubcommands(command: string): string[] {
  const results: string[] = []
  let current = ""
  let inSingleQuote = false
  let inDoubleQuote = false
  let escaped = false

  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!

    if (escaped) {
      current += ch
      escaped = false
      continue
    }

    if (ch === "\\" && !inSingleQuote) {
      current += ch
      escaped = true
      continue
    }

    if (ch === "'" && !inDoubleQuote) {
      current += ch
      inSingleQuote = !inSingleQuote
      continue
    }

    if (ch === '"' && !inSingleQuote) {
      current += ch
      inDoubleQuote = !inDoubleQuote
      continue
    }

    if (inSingleQuote || inDoubleQuote) {
      current += ch
      continue
    }

    // Check for compound operators
    if (ch === "|") {
      if (command[i + 1] === "|") {
        // ||
        results.push(current)
        current = ""
        i++ // skip second |
        continue
      }
      // | (pipe)
      results.push(current)
      current = ""
      continue
    }

    if (ch === "&" && command[i + 1] === "&") {
      // &&
      results.push(current)
      current = ""
      i++ // skip second &
      continue
    }

    if (ch === ";") {
      results.push(current)
      current = ""
      continue
    }

    current += ch
  }

  if (current.trim()) {
    results.push(current)
  }

  return results.map((s) => s.trim()).filter((s) => s.length > 0)
}

/**
 * Tokenize a simple command string into individual tokens.
 * Handles basic quoting (single quotes, double quotes, backslash escapes).
 * Does NOT handle complex shell constructs (command substitution, etc.)
 * — those are already rejected by containsUnsafeExpansion.
 */
function tokenize(command: string): string[] {
  const tokens: string[] = []
  let current = ""
  let inSingleQuote = false
  let inDoubleQuote = false
  let escaped = false

  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!

    if (escaped) {
      current += ch
      escaped = false
      continue
    }

    if (ch === "\\" && !inSingleQuote) {
      escaped = true
      // In double quotes, backslash only escapes $, `, ", \, newline
      if (inDoubleQuote) {
        const next = command[i + 1]
        if (next && !"$`\"\\\n".includes(next)) {
          current += ch // literal backslash
        }
      }
      continue
    }

    if (ch === "'" && !inDoubleQuote) {
      inSingleQuote = !inSingleQuote
      continue
    }

    if (ch === '"' && !inSingleQuote) {
      inDoubleQuote = !inDoubleQuote
      continue
    }

    if (!inSingleQuote && !inDoubleQuote && /\s/.test(ch)) {
      if (current.length > 0) {
        tokens.push(current)
        current = ""
      }
      continue
    }

    current += ch
  }

  if (current.length > 0) {
    tokens.push(current)
  }

  return tokens
}

/**
 * Validate flags of a tokenized command against a CommandConfig.
 * Returns true if all flags are in the safe set with valid argument types.
 *
 * Reference: CC validateFlags()
 */
function validateFlags(tokens: string[], startIndex: number, config: CommandConfig): boolean {
  let i = startIndex

  while (i < tokens.length) {
    const token = tokens[i]
    if (!token) {
      i++
      continue
    }

    // End of options marker
    if (token === "--") {
      i++
      break // Everything after -- is positional args
    }

    if (token.startsWith("-") && token.length > 1) {
      // Handle --flag=value format
      const hasEquals = token.includes("=")
      const eqIdx = token.indexOf("=")
      const flag = hasEquals ? token.slice(0, eqIdx) : token
      const inlineValue = hasEquals ? token.slice(eqIdx + 1) : ""

      if (!flag) return false

      const flagArgType = config.safeFlags[flag]

      if (!flagArgType) {
        // Special case: git -<number> shorthand (e.g., git log -5)
        if (flag.match(/^-\d+$/)) {
          i++
          continue
        }

        // Handle combined short flags (e.g., -nr, -la)
        // SECURITY: All bundled flags must be 'none' type to avoid
        // parser differential with GNU getopt
        if (flag.startsWith("-") && !flag.startsWith("--") && flag.length > 2) {
          let allValid = true
          for (let j = 1; j < flag.length; j++) {
            const singleFlag = "-" + flag[j]
            const singleType = config.safeFlags[singleFlag]
            if (!singleType || singleType !== "none") {
              allValid = false
              break
            }
          }
          if (allValid) {
            i++
            continue
          }

          // Handle flags with directly attached numeric arguments (e.g., -A20, -B10)
          // for grep and rg style commands
          if (flag.length > 2 && !flag.startsWith("--")) {
            const potentialFlag = flag.substring(0, 2)
            const potentialValue = flag.substring(2)
            const potentialType = config.safeFlags[potentialFlag]
            if (potentialType && (potentialType === "number" || potentialType === "string") && /^\d+$/.test(potentialValue)) {
              i++
              continue
            }
          }

          return false // Unknown combined flag
        }

        return false // Unknown flag
      }

      // Validate flag arguments
      if (flagArgType === "none") {
        if (hasEquals) return false // Flag should not have a value
        i++
      } else {
        let argValue: string
        if (hasEquals) {
          argValue = inlineValue
          i++
        } else {
          // Next token is the argument
          if (i + 1 >= tokens.length) return false // Missing required argument
          const nextToken = tokens[i + 1]
          // SECURITY: Reject flag arguments that start with - (could be flag injection)
          // Exception: git --sort allows - prefix for reverse sorting
          if (nextToken && nextToken.startsWith("-") && nextToken.length > 1) {
            // Check if it looks like a flag (not a negative number)
            if (!/^-\d+$/.test(nextToken)) {
              return false
            }
          }
          argValue = nextToken || ""
          i += 2
        }

        // Validate argument based on type
        switch (flagArgType) {
          case "number":
            if (!/^\d+$/.test(argValue)) return false
            break
          case "string":
            // Any string is valid
            break
        }
      }
    } else {
      // Positional argument — allowed for most commands
      if (config.allowPositionalArgs === false) return false
      i++
    }
  }

  return true
}

/**
 * Check if a single (non-compound) command is read-only.
 * This is the core validation function.
 */
function isSingleCommandReadOnly(command: string): boolean {
  let testCommand = command.trim()

  // Handle common stderr-to-stdout redirection
  if (testCommand.endsWith(" 2>&1")) {
    testCommand = testCommand.slice(0, -5).trim()
  }

  // Strip trailing redirections to /dev/null (safe, just suppresses output)
  // Handle: >/dev/null, 2>/dev/null, &>/dev/null, 2>&1 >/dev/null
  testCommand = testCommand
    .replace(/\s+2>&1\s*$/, "")
    .replace(/\s+[12&]?>\s*\/dev\/null\s*/g, " ")
    .trim()

  if (!testCommand) return false

  // SECURITY: Reject commands with UNC paths (WebDAV/SMB credential theft)
  if (containsUncPath(testCommand)) return false

  // SECURITY: Reject commands with unquoted shell expansions
  if (containsUnsafeExpansion(testCommand)) return false

  // 1. Try exact regex matches first
  for (const { pattern } of EXACT_MATCH_REGEXES) {
    if (pattern.test(testCommand)) {
      // Additional git safety checks
      if (testCommand.includes("git")) {
        if (/\s-c[\s=]/.test(testCommand)) return false
        if (/\s--exec-path[\s=]/.test(testCommand)) return false
        if (/\s--config-env[\s=]/.test(testCommand)) return false
      }
      return true
    }
  }

  // 2. Try flag-based validation via COMMAND_ALLOWLIST
  const tokens = tokenize(testCommand)
  if (tokens.length === 0) return false

  // Find matching command config (try multi-word commands first)
  let matchedConfig: CommandConfig | undefined
  let commandTokenCount = 0

  // Sort by longest prefix first for correct matching
  const entries = Object.entries(COMMAND_ALLOWLIST).sort((a, b) => b[0].split(" ").length - a[0].split(" ").length)

  for (const [cmdPattern, config] of entries) {
    const cmdTokens = cmdPattern.split(" ")
    if (tokens.length >= cmdTokens.length) {
      let matches = true
      for (let k = 0; k < cmdTokens.length; k++) {
        if (tokens[k] !== cmdTokens[k]) {
          matches = false
          break
        }
      }
      if (matches) {
        matchedConfig = config
        commandTokenCount = cmdTokens.length
        break
      }
    }
  }

  if (!matchedConfig) {
    // 3. Try simple read-only commands (no flag validation needed)
    const cmd = tokens[0]
    if (cmd && SIMPLE_READONLY_COMMANDS.has(cmd)) {
      // Simple regex: no shell metacharacters
      const safeArgPattern = /^[^<>()$`|{}&;\n\r]*$/
      const argsStr = testCommand.slice(cmd.length)
      return safeArgPattern.test(argsStr)
    }
    return false
  }

  // SECURITY: Check for $ in any argument token (variable expansion bypass)
  for (let k = commandTokenCount; k < tokens.length; k++) {
    const token = tokens[k]
    if (!token) continue
    if (token.includes("$")) return false
    // Brace expansion check: {X,Y} or {X..Y}
    if (token.includes("{") && (token.includes(",") || token.includes(".."))) return false
  }

  // Run flag validation
  if (!validateFlags(tokens, commandTokenCount, matchedConfig)) {
    return false
  }

  // Run custom danger callback if present
  if (matchedConfig.isDangerous) {
    const args = tokens.slice(commandTokenCount)
    if (matchedConfig.isDangerous(testCommand, args)) {
      return false
    }
  }

  // Additional git safety: block -c, --exec-path, --config-env for all git commands
  if (tokens[0] === "git") {
    if (/\s-c[\s=]/.test(testCommand)) return false
    if (/\s--exec-path[\s=]/.test(testCommand)) return false
    if (/\s--config-env[\s=]/.test(testCommand)) return false
  }

  // Block backticks in non-regex commands
  if (testCommand.includes("`")) return false

  // Block newlines/carriage returns in grep/rg patterns
  if ((tokens[0] === "rg" || tokens[0] === "grep") && /[\n\r]/.test(testCommand)) return false

  return true
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Check if a bash command is read-only and can be auto-approved
 * without user confirmation.
 *
 * This is the single entry point for the read-only validation system.
 * It handles compound commands by splitting and validating each sub-command.
 *
 * @param command - The raw command string to validate
 * @returns ReadOnlyResult with `readonly: true` if the command is safe to auto-approve
 */
export function isReadOnlyCommand(command: string): ReadOnlyResult {
  if (!command || !command.trim()) {
    return { readonly: false, reason: "Empty command" }
  }

  const trimmed = command.trim()

  // SECURITY: Reject commands with UNC paths early (before splitting)
  if (containsUncPath(trimmed)) {
    return { readonly: false, reason: "Command contains Windows UNC path (potential credential theft)" }
  }

  // SECURITY: Reject commands with unquoted expansions early (before splitting)
  if (containsUnsafeExpansion(trimmed)) {
    return { readonly: false, reason: "Command contains variable expansion or glob that cannot be statically analyzed" }
  }

  // Split compound command into sub-commands
  const subcommands = splitSubcommands(trimmed)

  if (subcommands.length === 0) {
    return { readonly: false, reason: "No sub-commands found" }
  }

  // SECURITY: If compound command has cd + git, reject (sandbox escape via fake hooks)
  const hasGit = subcommands.some((sub) => {
    const tokens = tokenize(sub.trim())
    return tokens[0] === "git" || (tokens.length > 1 && tokens[0] === "git")
  })
  const hasCd = subcommands.some((sub) => {
    const tokens = tokenize(sub.trim())
    const cmd = tokens[0]?.toLowerCase()
    return cmd === "cd" || cmd === "pushd" || cmd === "popd"
  })
  if (hasGit && hasCd) {
    return { readonly: false, reason: "Compound command with cd and git (potential sandbox escape)" }
  }

  // Check each sub-command
  for (const sub of subcommands) {
    if (!isSingleCommandReadOnly(sub)) {
      return { readonly: false, reason: `Sub-command is not read-only: ${sub.trim().slice(0, 80)}` }
    }
  }

  return { readonly: true }
}
