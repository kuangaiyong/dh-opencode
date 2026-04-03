/**
 * Multi-language query expansion for FTS keyword search.
 *
 * When no embedding provider is available (or as a supplement to vector search),
 * FTS works best with specific keywords. Users often ask conversational queries
 * like "that thing we discussed yesterday" or "之前讨论的那个方案".
 *
 * This module extracts meaningful keywords from such queries by filtering
 * stop words across 7 languages (EN/ES/PT/AR/KO/JA/ZH) and performing
 * CJK-aware tokenization.
 *
 * Ported from openclaw's memory-host-sdk query-expansion.ts.
 */

// ---------------------------------------------------------------------------
// Stop word sets — 7 languages
// ---------------------------------------------------------------------------

const STOP_EN = new Set([
  // Articles and determiners
  "a", "an", "the", "this", "that", "these", "those",
  // Pronouns
  "i", "me", "my", "we", "our", "you", "your", "he", "she", "it", "they", "them",
  // Common verbs
  "is", "are", "was", "were", "be", "been", "being",
  "have", "has", "had", "do", "does", "did",
  "will", "would", "could", "should", "can", "may", "might",
  // Prepositions
  "in", "on", "at", "to", "for", "of", "with", "by", "from", "about",
  "into", "through", "during", "before", "after", "above", "below",
  "between", "under", "over",
  // Conjunctions
  "and", "or", "but", "if", "then", "because", "as", "while",
  "when", "where", "what", "which", "who", "how", "why",
  // Time references (vague)
  "yesterday", "today", "tomorrow", "earlier", "later", "recently",
  "ago", "just", "now",
  // Vague references
  "thing", "things", "stuff", "something", "anything", "everything", "nothing",
  // Question words
  "please", "help", "find", "show", "get", "tell", "give",
])

const STOP_ES = new Set([
  "el", "la", "los", "las", "un", "una", "unos", "unas", "este", "esta", "ese", "esa",
  "yo", "me", "mi", "nosotros", "nosotras", "tu", "tus", "usted", "ustedes", "ellos", "ellas",
  "de", "del", "a", "en", "con", "por", "para", "sobre", "entre",
  "y", "o", "pero", "si", "porque", "como",
  "es", "son", "fue", "fueron", "ser", "estar", "haber", "tener", "hacer",
  "ayer", "hoy", "mañana", "antes", "despues", "después", "ahora", "recientemente",
  "que", "qué", "cómo", "cuando", "cuándo", "donde", "dónde", "porqué", "favor", "ayuda",
])

const STOP_PT = new Set([
  "o", "a", "os", "as", "um", "uma", "uns", "umas", "este", "esta", "esse", "essa",
  "eu", "me", "meu", "minha", "nos", "nós", "você", "vocês", "ele", "ela", "eles", "elas",
  "de", "do", "da", "em", "com", "por", "para", "sobre", "entre",
  "e", "ou", "mas", "se", "porque", "como",
  "é", "são", "foi", "foram", "ser", "estar", "ter", "fazer",
  "ontem", "hoje", "amanhã", "antes", "depois", "agora", "recentemente",
  "que", "quê", "quando", "onde", "porquê", "favor", "ajuda",
])

const STOP_AR = new Set([
  "ال", "و", "أو", "لكن", "ثم", "بل",
  "أنا", "نحن", "هو", "هي", "هم", "هذا", "هذه", "ذلك", "تلك", "هنا", "هناك",
  "من", "إلى", "الى", "في", "على", "عن", "مع", "بين", "ل", "ب", "ك",
  "كان", "كانت", "يكون", "تكون", "صار", "أصبح", "يمكن", "ممكن",
  "بالأمس", "امس", "اليوم", "غدا", "الآن", "قبل", "بعد", "مؤخرا",
  "لماذا", "كيف", "ماذا", "متى", "أين", "هل", "من فضلك", "فضلا", "ساعد",
])

const STOP_KO = new Set([
  // Particles
  "은", "는", "이", "가", "을", "를", "의", "에", "에서", "로", "으로",
  "와", "과", "도", "만", "까지", "부터", "한테", "에게", "께",
  "처럼", "같이", "보다", "마다", "밖에", "대로",
  // Pronouns
  "나", "나는", "내가", "나를", "너", "우리", "저", "저희",
  "그", "그녀", "그들", "이것", "저것", "그것", "여기", "저기", "거기",
  // Common verbs
  "있다", "없다", "하다", "되다", "이다", "아니다", "보다", "주다", "오다", "가다",
  // Vague nouns
  "것", "거", "등", "수", "때", "곳", "중", "분",
  // Adverbs
  "잘", "더", "또", "매우", "정말", "아주", "많이", "너무", "좀",
  // Conjunctions
  "그리고", "하지만", "그래서", "그런데", "그러나", "또는", "그러면",
  // Question words
  "왜", "어떻게", "뭐", "언제", "어디", "누구", "무엇", "어떤",
  // Time (vague)
  "어제", "오늘", "내일", "최근", "지금", "아까", "나중", "전에",
  // Request
  "제발", "부탁",
])

const STOP_JA = new Set([
  "これ", "それ", "あれ", "この", "その", "あの", "ここ", "そこ", "あそこ",
  "する", "した", "して", "です", "ます", "いる", "ある", "なる", "できる",
  "の", "こと", "もの", "ため", "そして", "しかし", "また", "でも",
  "から", "まで", "より", "だけ",
  "なぜ", "どう", "何", "いつ", "どこ", "誰", "どれ",
  "昨日", "今日", "明日", "最近", "今", "さっき", "前", "後",
])

const STOP_ZH = new Set([
  // Pronouns
  "我", "我们", "你", "你们", "他", "她", "它", "他们",
  "这", "那", "这个", "那个", "这些", "那些",
  // Auxiliary words
  "的", "了", "着", "过", "得", "地", "吗", "呢", "吧", "啊", "呀", "嘛", "啦",
  // Common verbs (vague)
  "是", "有", "在", "被", "把", "给", "让", "用", "到", "去", "来",
  "做", "说", "看", "找", "想", "要", "能", "会", "可以",
  // Prepositions and conjunctions
  "和", "与", "或", "但", "但是", "因为", "所以", "如果", "虽然",
  "而", "也", "都", "就", "还", "又", "再", "才", "只",
  // Time (vague)
  "之前", "以前", "之后", "以后", "刚才", "现在", "昨天", "今天", "明天", "最近",
  // Vague references
  "东西", "事情", "事", "什么", "哪个", "哪些", "怎么", "为什么", "多少",
  // Request words
  "请", "帮", "帮忙", "告诉",
])

// ---------------------------------------------------------------------------
// Korean particle stripping
// ---------------------------------------------------------------------------

const KO_PARTICLES = [
  "에서", "으로", "에게", "한테", "처럼", "같이", "보다", "까지", "부터", "마다", "밖에", "대로",
  "은", "는", "이", "가", "을", "를", "의", "에", "로", "와", "과", "도", "만",
].sort((a, b) => b.length - a.length)

function stripKorean(token: string): string | null {
  for (const p of KO_PARTICLES) {
    if (token.length > p.length && token.endsWith(p)) return token.slice(0, -p.length)
  }
  return null
}

function usefulStem(stem: string): boolean {
  if (/[\uac00-\ud7af]/.test(stem)) return stem.length >= 2
  return /^[a-z0-9_]+$/i.test(stem)
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

function isStop(token: string): boolean {
  return (
    STOP_EN.has(token) ||
    STOP_ES.has(token) ||
    STOP_PT.has(token) ||
    STOP_AR.has(token) ||
    STOP_ZH.has(token) ||
    STOP_KO.has(token) ||
    STOP_JA.has(token)
  )
}

function valid(token: string): boolean {
  if (!token) return false
  // Short English words are likely stop words or fragments
  if (/^[a-zA-Z]+$/.test(token) && token.length < 3) return false
  // Pure numbers not useful for semantic search
  if (/^\d+$/.test(token)) return false
  // All punctuation
  if (/^[\p{P}\p{S}]+$/u.test(token)) return false
  return true
}

/**
 * Tokenize text with CJK awareness.
 * For Chinese: character unigrams + bigrams (for unicode61 FTS).
 * For Japanese: script-based splitting.
 * For Korean: whole words with particle stripping.
 */
function tokenize(text: string): string[] {
  const tokens: string[] = []
  const normalized = text.toLowerCase().trim()
  const segments = normalized.split(/[\s\p{P}]+/u).filter(Boolean)

  for (const seg of segments) {
    // Japanese (hiragana/katakana present)
    if (/[\u3040-\u30ff]/.test(seg)) {
      const parts = seg.match(/[a-z0-9_]+|[\u30a0-\u30ffー]+|[\u4e00-\u9fff]+|[\u3040-\u309f]{2,}/g) ?? []
      for (const part of parts) {
        if (/^[\u4e00-\u9fff]+$/.test(part)) {
          tokens.push(part)
          for (let i = 0; i < part.length - 1; i++) tokens.push(part[i] + part[i + 1])
        } else {
          tokens.push(part)
        }
      }
    }
    // Chinese (CJK unified ideographs)
    else if (/[\u4e00-\u9fff]/.test(seg)) {
      const chars = Array.from(seg).filter((c) => /[\u4e00-\u9fff]/.test(c))
      tokens.push(...chars)
      for (let i = 0; i < chars.length - 1; i++) tokens.push(chars[i] + chars[i + 1])
    }
    // Korean (Hangul syllables and jamo)
    else if (/[\uac00-\ud7af\u3131-\u3163]/.test(seg)) {
      const stem = stripKorean(seg)
      const stemStop = stem !== null && STOP_KO.has(stem)
      if (!STOP_KO.has(seg) && !stemStop) tokens.push(seg)
      if (stem && !STOP_KO.has(stem) && usefulStem(stem)) tokens.push(stem)
    }
    // Latin / other
    else {
      tokens.push(seg)
    }
  }
  return tokens
}

/**
 * Extract keywords from a conversational query for FTS search.
 * Filters stop words across 7 languages and performs CJK-aware tokenization.
 *
 * Examples:
 * - "that thing we discussed about the API" → ["discussed", "api"]
 * - "之前讨论的那个方案" → ["讨", "论", "方", "案", "讨论", "方案"]
 * - "what was the solution for the bug" → ["solution", "bug"]
 */
export function extractKeywords(query: string): string[] {
  const tokens = tokenize(query)
  const keywords: string[] = []
  const seen = new Set<string>()

  for (const token of tokens) {
    if (isStop(token)) continue
    if (!valid(token)) continue
    if (seen.has(token)) continue
    seen.add(token)
    keywords.push(token)
  }
  return keywords
}

/**
 * Expand a query for FTS search.
 * Returns both the original query and extracted keywords joined with OR.
 */
export function expandQuery(query: string): {
  original: string
  keywords: string[]
  expanded: string
} {
  const original = query.trim()
  const keywords = extractKeywords(original)
  const expanded = keywords.length > 0 ? `${original} OR ${keywords.join(" OR ")}` : original
  return { original, keywords, expanded }
}
