import { Plugin } from "../plugin"
import { Format } from "../format"
import { LSP } from "../lsp"
import { File } from "../file"
import { FileWatcher } from "../file/watcher"
import { Snapshot } from "../snapshot"
import { Project } from "./project"
import { Vcs } from "./vcs"
import { Bus } from "../bus"
import { Command } from "../command"
import { Instance } from "./instance"
import { Log } from "@/util/log"
import { ShareNext } from "@/share/share-next"
import { Config } from "@/config/config"
import { Global } from "@/global"
import { Memory } from "@/memory"
import { SessionSave } from "@/memory/session-save"
import { MemoryFlush } from "@/memory/flush"
import { AutoCapture } from "@/memory/capture"
import { Consolidate } from "@/memory/consolidate"

export async function InstanceBootstrap() {
  Log.Default.info("bootstrapping", { directory: Instance.directory })
  await Plugin.init()
  ShareNext.init()
  Format.init()
  await LSP.init()
  File.init()
  FileWatcher.init()
  Vcs.init()
  Snapshot.init()

  Bus.subscribe(Command.Event.Executed, async (payload) => {
    if (payload.properties.name === Command.Default.INIT) {
      Project.setInitialized(Instance.project.id)
    }
  })

  // initialise cross-session memory if enabled
  try {
    const cfg = await Config.get()
    if (cfg.memory?.enabled) {
      await Memory.init(Global.Path.config, {
        provider: cfg.memory.provider,
        model: cfg.memory.model,
      })
      SessionSave.init()
      MemoryFlush.init()
      AutoCapture.init()
      // consolidate recent daily memory into MEMORY.md (at most once per day)
      Consolidate.run().catch((err) =>
        Log.Default.warn("memory consolidation failed", { error: String(err) }),
      )
      Log.Default.info("memory system enabled", { directory: Global.Path.config })
    }
  } catch (err) {
    Log.Default.warn("failed to initialise memory system", { error: String(err) })
  }
}
