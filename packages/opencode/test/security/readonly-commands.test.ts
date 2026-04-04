import { describe, expect, test } from "bun:test"
import { isReadOnlyCommand } from "../../src/security/readonly-commands"

describe("readonly-commands", () => {
  // ─── Simple Read-Only Commands ─────────────────────────────────────

  describe("simple readonly commands", () => {
    const simpleCommands = [
      "cat file.txt",
      "head -n 10 file.txt",
      "tail -f log.txt",
      "wc -l file.txt",
      "stat file.txt",
      "diff a.txt b.txt",
      "du -sh .",
      "df -h",
      "id",
      "uname -a",
      "which python",
      "sleep 1",
      "basename /path/to/file.txt",
      "dirname /path/to/file.txt",
      "cut -d: -f1 /etc/passwd",
      "tr a-z A-Z",
      "seq 1 10",
      "date",
      "hostname",
      "uptime",
      "cal",
      "free -h",
    ]

    for (const cmd of simpleCommands) {
      test(`allows: ${cmd}`, () => {
        const result = isReadOnlyCommand(cmd)
        expect(result.readonly).toBe(true)
      })
    }

    test("rejects empty command", () => {
      expect(isReadOnlyCommand("").readonly).toBe(false)
    })

    test("rejects whitespace-only command", () => {
      expect(isReadOnlyCommand("   ").readonly).toBe(false)
    })
  })

  // ─── Exact-Match Regex Commands ────────────────────────────────────

  describe("exact-match regex commands", () => {
    test("allows echo with simple args", () => {
      expect(isReadOnlyCommand("echo hello world").readonly).toBe(true)
    })

    test("allows echo with single-quoted args", () => {
      expect(isReadOnlyCommand("echo 'hello world'").readonly).toBe(true)
    })

    test("allows echo with double-quoted safe args", () => {
      expect(isReadOnlyCommand('echo "hello world"').readonly).toBe(true)
    })

    test("rejects echo with variable expansion", () => {
      expect(isReadOnlyCommand("echo $HOME").readonly).toBe(false)
    })

    test("allows pwd", () => {
      expect(isReadOnlyCommand("pwd").readonly).toBe(true)
    })

    test("rejects pwd with args", () => {
      expect(isReadOnlyCommand("pwd /tmp").readonly).toBe(false)
    })

    test("allows whoami", () => {
      expect(isReadOnlyCommand("whoami").readonly).toBe(true)
    })

    test("allows node -v", () => {
      expect(isReadOnlyCommand("node -v").readonly).toBe(true)
    })

    test("allows node --version", () => {
      expect(isReadOnlyCommand("node --version").readonly).toBe(true)
    })

    test("rejects node with script (not version)", () => {
      expect(isReadOnlyCommand("node script.js").readonly).toBe(false)
    })

    test("rejects node -v --run task", () => {
      // SECURITY: node -v --run <task> executes package.json scripts
      expect(isReadOnlyCommand("node -v --run test").readonly).toBe(false)
    })

    test("allows ls", () => {
      expect(isReadOnlyCommand("ls").readonly).toBe(true)
    })

    test("allows ls -la", () => {
      expect(isReadOnlyCommand("ls -la").readonly).toBe(true)
    })

    test("allows ls with path", () => {
      expect(isReadOnlyCommand("ls /tmp").readonly).toBe(true)
    })

    test("allows cd with path", () => {
      expect(isReadOnlyCommand("cd /tmp").readonly).toBe(true)
    })

    test("allows cd with quoted path", () => {
      expect(isReadOnlyCommand("cd 'my project'").readonly).toBe(true)
    })

    test("allows history", () => {
      expect(isReadOnlyCommand("history").readonly).toBe(true)
    })

    test("allows history with number", () => {
      expect(isReadOnlyCommand("history 50").readonly).toBe(true)
    })

    test("allows alias", () => {
      expect(isReadOnlyCommand("alias").readonly).toBe(true)
    })

    test("allows ip addr", () => {
      expect(isReadOnlyCommand("ip addr").readonly).toBe(true)
    })

    test("allows find without dangerous flags", () => {
      expect(isReadOnlyCommand("find . -name '*.ts' -type f").readonly).toBe(true)
    })

    test("rejects find with -exec", () => {
      expect(isReadOnlyCommand("find . -name '*.ts' -exec rm {} ;").readonly).toBe(false)
    })

    test("rejects find with -delete", () => {
      expect(isReadOnlyCommand("find . -name '*.bak' -delete").readonly).toBe(false)
    })
  })

  // ─── Git Commands ──────────────────────────────────────────────────

  describe("git commands", () => {
    test("allows git status", () => {
      expect(isReadOnlyCommand("git status").readonly).toBe(true)
    })

    test("allows git status --short", () => {
      expect(isReadOnlyCommand("git status --short").readonly).toBe(true)
    })

    test("allows git diff", () => {
      expect(isReadOnlyCommand("git diff").readonly).toBe(true)
    })

    test("allows git diff --cached", () => {
      expect(isReadOnlyCommand("git diff --cached").readonly).toBe(true)
    })

    test("allows git diff --stat", () => {
      expect(isReadOnlyCommand("git diff --stat").readonly).toBe(true)
    })

    test("allows git log", () => {
      expect(isReadOnlyCommand("git log").readonly).toBe(true)
    })

    test("allows git log --oneline -n 10", () => {
      expect(isReadOnlyCommand("git log --oneline -n 10").readonly).toBe(true)
    })

    test("allows git log with numeric shorthand", () => {
      expect(isReadOnlyCommand("git log -5").readonly).toBe(true)
    })

    test("allows git show", () => {
      expect(isReadOnlyCommand("git show").readonly).toBe(true)
    })

    test("allows git show HEAD", () => {
      expect(isReadOnlyCommand("git show HEAD").readonly).toBe(true)
    })

    test("allows git blame file", () => {
      expect(isReadOnlyCommand("git blame src/index.ts").readonly).toBe(true)
    })

    test("allows git blame with flags", () => {
      expect(isReadOnlyCommand("git blame -L 10,20 src/index.ts").readonly).toBe(true)
    })

    test("allows git branch --list", () => {
      expect(isReadOnlyCommand("git branch --list").readonly).toBe(true)
    })

    test("allows git branch -a", () => {
      expect(isReadOnlyCommand("git branch -a").readonly).toBe(true)
    })

    test("rejects git branch with name (creates branch)", () => {
      expect(isReadOnlyCommand("git branch new-feature").readonly).toBe(false)
    })

    test("allows git tag --list", () => {
      expect(isReadOnlyCommand("git tag --list").readonly).toBe(true)
    })

    test("allows git tag -l", () => {
      expect(isReadOnlyCommand("git tag -l").readonly).toBe(true)
    })

    test("rejects git tag with name (creates tag)", () => {
      expect(isReadOnlyCommand("git tag v1.0.0").readonly).toBe(false)
    })

    test("allows git remote", () => {
      expect(isReadOnlyCommand("git remote").readonly).toBe(true)
    })

    test("allows git remote -v", () => {
      expect(isReadOnlyCommand("git remote -v").readonly).toBe(true)
    })

    test("allows git remote show origin", () => {
      expect(isReadOnlyCommand("git remote show origin").readonly).toBe(true)
    })

    test("rejects git remote add", () => {
      expect(isReadOnlyCommand("git remote add origin url").readonly).toBe(false)
    })

    test("allows git ls-files", () => {
      expect(isReadOnlyCommand("git ls-files").readonly).toBe(true)
    })

    test("allows git stash list", () => {
      expect(isReadOnlyCommand("git stash list").readonly).toBe(true)
    })

    test("allows git config --get user.name", () => {
      expect(isReadOnlyCommand("git config --get user.name").readonly).toBe(true)
    })

    test("allows git config --list", () => {
      expect(isReadOnlyCommand("git config --list").readonly).toBe(true)
    })

    test("rejects git config without read flag", () => {
      expect(isReadOnlyCommand("git config user.name 'New Name'").readonly).toBe(false)
    })

    test("allows git rev-parse HEAD", () => {
      expect(isReadOnlyCommand("git rev-parse HEAD").readonly).toBe(true)
    })

    test("allows git rev-parse --show-toplevel", () => {
      expect(isReadOnlyCommand("git rev-parse --show-toplevel").readonly).toBe(true)
    })

    test("allows git describe --tags", () => {
      expect(isReadOnlyCommand("git describe --tags").readonly).toBe(true)
    })

    test("allows git cat-file -p HEAD", () => {
      expect(isReadOnlyCommand("git cat-file -p HEAD").readonly).toBe(true)
    })

    test("allows git reflog", () => {
      expect(isReadOnlyCommand("git reflog").readonly).toBe(true)
    })

    test("allows git shortlog -sn", () => {
      expect(isReadOnlyCommand("git shortlog -sn").readonly).toBe(true)
    })

    // ── Git Safety Checks ──

    test("rejects git -c with arbitrary config", () => {
      expect(isReadOnlyCommand("git -c core.fsmonitor=evil status").readonly).toBe(false)
    })

    test("rejects git --exec-path", () => {
      expect(isReadOnlyCommand("git --exec-path=/tmp status").readonly).toBe(false)
    })

    test("rejects git --config-env", () => {
      expect(isReadOnlyCommand("git --config-env=core.x=VAR status").readonly).toBe(false)
    })

    test("rejects git ls-remote with URL", () => {
      expect(isReadOnlyCommand("git ls-remote https://evil.com/repo").readonly).toBe(false)
    })

    test("rejects git push", () => {
      expect(isReadOnlyCommand("git push").readonly).toBe(false)
    })

    test("rejects git commit", () => {
      expect(isReadOnlyCommand("git commit -m 'msg'").readonly).toBe(false)
    })

    test("rejects git add", () => {
      expect(isReadOnlyCommand("git add .").readonly).toBe(false)
    })

    test("rejects git checkout", () => {
      expect(isReadOnlyCommand("git checkout main").readonly).toBe(false)
    })
  })

  // ─── Non-Git Flag Validation ───────────────────────────────────────

  describe("non-git flag validation", () => {
    test("allows grep with standard flags", () => {
      expect(isReadOnlyCommand("grep -rn 'pattern' .").readonly).toBe(true)
    })

    test("allows grep with -A20 (attached numeric)", () => {
      expect(isReadOnlyCommand("grep -A20 pattern file.txt").readonly).toBe(true)
    })

    test("allows rg with flags", () => {
      expect(isReadOnlyCommand("rg --color=auto -i pattern").readonly).toBe(true)
    })

    test("allows tree with depth", () => {
      expect(isReadOnlyCommand("tree -L 3").readonly).toBe(true)
    })

    test("rejects tree with -o (output to file)", () => {
      expect(isReadOnlyCommand("tree -o output.txt").readonly).toBe(false)
    })

    test("allows sort with flags", () => {
      expect(isReadOnlyCommand("sort -nr file.txt").readonly).toBe(true)
    })

    test("allows file with flags", () => {
      expect(isReadOnlyCommand("file --mime-type test.bin").readonly).toBe(true)
    })
  })

  // ─── Compound Commands ─────────────────────────────────────────────

  describe("compound commands", () => {
    test("allows pipe of readonly commands", () => {
      expect(isReadOnlyCommand("cat file.txt | grep pattern").readonly).toBe(true)
    })

    test("allows && of readonly commands", () => {
      expect(isReadOnlyCommand("git status && git log -1").readonly).toBe(true)
    })

    test("allows || of readonly commands", () => {
      expect(isReadOnlyCommand("cat file.txt || echo 'not found'").readonly).toBe(true)
    })

    test("allows semicolon of readonly commands", () => {
      expect(isReadOnlyCommand("git status; git diff").readonly).toBe(true)
    })

    test("rejects pipe to non-readonly", () => {
      expect(isReadOnlyCommand("cat file | rm -rf /").readonly).toBe(false)
    })

    test("rejects && with non-readonly", () => {
      expect(isReadOnlyCommand("ls && rm file.txt").readonly).toBe(false)
    })

    test("rejects cd + git compound (sandbox escape)", () => {
      expect(isReadOnlyCommand("cd /tmp && git status").readonly).toBe(false)
    })

    test("rejects pushd + git compound", () => {
      expect(isReadOnlyCommand("pushd /tmp; git log").readonly).toBe(false)
    })
  })

  // ─── Unsafe Expansions ─────────────────────────────────────────────

  describe("unsafe expansions", () => {
    test("rejects $VAR expansion", () => {
      expect(isReadOnlyCommand("cat $HOME/file.txt").readonly).toBe(false)
    })

    test("rejects ${VAR} expansion", () => {
      expect(isReadOnlyCommand("cat ${HOME}/file.txt").readonly).toBe(false)
    })

    test("rejects $() command substitution", () => {
      expect(isReadOnlyCommand("cat $(echo file.txt)").readonly).toBe(false)
    })

    test("rejects backtick substitution", () => {
      expect(isReadOnlyCommand("cat `echo file.txt`").readonly).toBe(false)
    })

    test("rejects glob *", () => {
      expect(isReadOnlyCommand("cat *.txt").readonly).toBe(false)
    })

    test("rejects glob ?", () => {
      expect(isReadOnlyCommand("cat file?.txt").readonly).toBe(false)
    })

    test("rejects glob [...]", () => {
      expect(isReadOnlyCommand("cat file[123].txt").readonly).toBe(false)
    })

    test("allows variable inside single quotes", () => {
      expect(isReadOnlyCommand("echo '$HOME'").readonly).toBe(true)
    })
  })

  // ─── UNC Paths ─────────────────────────────────────────────────────

  describe("UNC paths", () => {
    test("rejects backslash UNC", () => {
      expect(isReadOnlyCommand("cat \\\\server\\share\\file").readonly).toBe(false)
    })

    test("rejects forward-slash UNC", () => {
      expect(isReadOnlyCommand("cat //server/share/file").readonly).toBe(false)
    })
  })

  // ─── Non-Readonly Commands ─────────────────────────────────────────

  describe("non-readonly commands", () => {
    test("rejects rm", () => {
      expect(isReadOnlyCommand("rm file.txt").readonly).toBe(false)
    })

    test("rejects mkdir", () => {
      expect(isReadOnlyCommand("mkdir new_dir").readonly).toBe(false)
    })

    test("rejects mv", () => {
      expect(isReadOnlyCommand("mv a.txt b.txt").readonly).toBe(false)
    })

    test("rejects cp", () => {
      expect(isReadOnlyCommand("cp a.txt b.txt").readonly).toBe(false)
    })

    test("rejects python", () => {
      expect(isReadOnlyCommand("python script.py").readonly).toBe(false)
    })

    test("rejects node", () => {
      expect(isReadOnlyCommand("node script.js").readonly).toBe(false)
    })

    test("rejects npm install", () => {
      expect(isReadOnlyCommand("npm install").readonly).toBe(false)
    })

    test("rejects curl", () => {
      expect(isReadOnlyCommand("curl https://example.com").readonly).toBe(false)
    })

    test("rejects wget", () => {
      expect(isReadOnlyCommand("wget https://example.com").readonly).toBe(false)
    })

    test("rejects ssh", () => {
      expect(isReadOnlyCommand("ssh user@host").readonly).toBe(false)
    })

    test("rejects unknown commands", () => {
      expect(isReadOnlyCommand("unknown_command arg1 arg2").readonly).toBe(false)
    })
  })

  // ─── jq Command ────────────────────────────────────────────────────

  describe("jq command", () => {
    test("allows jq with filter and file", () => {
      expect(isReadOnlyCommand("jq '.key' data.json").readonly).toBe(true)
    })

    test("rejects jq with -f (from-file)", () => {
      expect(isReadOnlyCommand("jq -f script.jq data.json").readonly).toBe(false)
    })

    test("rejects jq with --rawfile", () => {
      expect(isReadOnlyCommand("jq --rawfile v file data.json").readonly).toBe(false)
    })

    test("rejects jq with env access", () => {
      expect(isReadOnlyCommand("jq 'env.SECRET' data.json").readonly).toBe(false)
    })
  })
})
