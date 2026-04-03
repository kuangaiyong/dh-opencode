import z from "zod"
import { Tool } from "./tool"
import { Memory } from "../memory"
import { looksLikeInjection } from "../memory/sanitize"

export const MemoryStoreTool = Tool.define("memory_store", async () => {
  return {
    description:
      "Store a new memory for future sessions. Use this to save important decisions, " +
      "preferences, facts, or context that should persist across conversations. " +
      "The memory is saved as a markdown file in the memory directory and indexed for search.",
    parameters: z.object({
      content: z
        .string()
        .describe("The text content to store as a memory (markdown supported)"),
      slug: z
        .string()
        .optional()
        .describe(
          "Short kebab-case identifier for the memory file (e.g. 'auth-decision'). " +
            "If omitted, a default slug is generated from the date.",
        ),
    }),
    async execute(params) {
      if (looksLikeInjection(params.content)) {
        return {
          title: "Memory rejected",
          metadata: {},
          output: "Content was rejected because it contains patterns that look like prompt injection.",
        }
      }

      const slug = params.slug || "memory"
      try {
        const filepath = await Memory.save(slug, params.content)
        return {
          title: "Memory stored",
          metadata: { path: filepath },
          output: `Memory saved to ${filepath}`,
        }
      } catch (err) {
        return {
          title: "Failed to store memory",
          metadata: {},
          output: `Error storing memory: ${err instanceof Error ? err.message : String(err)}`,
        }
      }
    },
  }
})
