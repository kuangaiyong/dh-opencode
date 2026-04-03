/**
 * Memory classification system — 5 categories.
 *
 * Classifies memory content into one of five categories using regex matching:
 * - preference: user likes, dislikes, style choices
 * - decision: choices, conclusions, architecture decisions
 * - entity: names, identifiers, references to people/projects
 * - fact: factual statements about locations, tools, processes
 * - other: anything that doesn't match the above
 *
 * Ported from openclaw's memory-lancedb classification logic.
 */

export type Category = "preference" | "decision" | "entity" | "fact" | "other"

const PREFERENCE = /\b(prefer|like|dislike|hate|love|favorite|favour|favor|rather|style|taste|want|wish)\b/i
const DECISION = /\b(decided|decision|chose|chosen|concluded|agreed|approach|strategy|resolved|settled|picked)\b/i
const ENTITY = /\b(name is|called|known as|named|alias|handle|username|team|project|repo)\b/i
const FACT = /\b(is located|works at|lives in|based in|runs on|built with|uses|version|port|path|url|endpoint)\b/i

/**
 * Classify a piece of text into one of 5 memory categories.
 * First matching pattern wins; defaults to "other".
 */
export function classify(text: string): Category {
  if (PREFERENCE.test(text)) return "preference"
  if (DECISION.test(text)) return "decision"
  if (ENTITY.test(text)) return "entity"
  if (FACT.test(text)) return "fact"
  return "other"
}
