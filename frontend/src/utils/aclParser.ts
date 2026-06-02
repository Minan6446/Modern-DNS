/**
 * BIND-style ACL line parser shared by the「区域选项」dialog.
 *
 * What kinds of tokens we accept per line
 * ───────────────────────────────────────
 *  - Empty lines & whitespace-only lines      → silently ignored
 *  - `# comment`  /  `// comment`              → treated as comments
 *  - `any` / `none` / `localhost` / `localnets`
 *                                              → BIND macros (passed through)
 *  - `192.0.2.10`                              → bare IPv4
 *  - `192.0.2.0/24`                            → IPv4 CIDR
 *  - `2001:db8::1`                             → bare IPv6
 *  - `2001:db8::/32`                           → IPv6 CIDR
 *  - `host.example.com`                        → DNS hostname (RFC 1123 form)
 *  - `!` prefix on any of the above            → BIND negation (block)
 *
 * Why we accept hostnames at all
 * ──────────────────────────────
 * BIND-style ACLs traditionally take literal addresses, but the engine
 * we plan to put behind these textareas will resolve hostnames on
 * config reload (one query per name, cached) so an operator can type
 * `office.internal.example` and have it Just Work. The parser doesn't
 * try to resolve here — it only validates the *shape* of the input
 * so we don't store obvious garbage.
 *
 * Why this lives in a util (not inside the dialog component)
 * ──────────────────────────────────────────────────────────
 * The same validation rules will apply to forward-rule ACL, security
 * BW-list, RPZ rule sources, etc. Keeping the parser stand-alone lets
 * those pages adopt it without dragging in Vue / Element Plus.
 */

export type AclLineKind =
  | 'empty'
  | 'comment'
  | 'macro'
  | 'ipv4'
  | 'ipv4-cidr'
  | 'ipv6'
  | 'ipv6-cidr'
  | 'hostname'

export interface AclLineResult {
  /** 1-based line number — convenient for displaying in the error list. */
  lineNumber: number
  /** Raw line content as the operator typed it (after newline split). */
  raw: string
  /** Kind of value parsed — `null` when invalid. */
  kind: AclLineKind | null
  /** Negated with `!` prefix (BIND syntax). Always false for invalid. */
  negated: boolean
  /** Localised error message when invalid; empty string otherwise. */
  error: string
}

export interface AclParseSummary {
  lines: AclLineResult[]
  /** Subset of `lines` with non-empty `error` — pre-filtered for UI. */
  errors: AclLineResult[]
  /** How many *non-empty, non-comment* entries we accepted. */
  validEntries: number
}

// Macros accepted verbatim. BIND defines a handful more (`localnets-any`
// etc.), but we keep the set small and explicit; new macros are a
// one-line addition.
const ACL_MACROS = new Set(['any', 'none', 'localhost', 'localnets'])

// ─── IPv4 ───────────────────────────────────────────────────────────────────
// Four 0-255 octets joined by dots. We deliberately use a strict
// regex instead of a parser combinator: the legal grammar is
// trivially regular and the regex form is faster + easier to
// audit than ad-hoc parsing.
const IPV4_OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
const IPV4_RE = new RegExp(`^${IPV4_OCTET}(\\.${IPV4_OCTET}){3}$`)
const IPV4_CIDR_RE = new RegExp(
  `^${IPV4_OCTET}(\\.${IPV4_OCTET}){3}/(3[0-2]|[12]?\\d)$`,
)

// ─── IPv6 ───────────────────────────────────────────────────────────────────
// Full IPv6 grammar is awkward in a single regex (compression with
// `::`, optional embedded IPv4); we use a permissive form that
// catches every well-formed v6 address and a few "looks right but
// isn't" forms. The follow-up engine resolver will reject malformed
// addresses authoritatively — our job here is only to filter obvious
// typos before they hit the DB.
const IPV6_BARE_RE = /^[0-9a-fA-F:]+$/
const IPV6_CIDR_RE = /^[0-9a-fA-F:]+\/(12[0-8]|1[01]\d|\d{1,2})$/

// Returns true when the candidate looks like an IPv6 *address* (no slash)
// and contains the structural cues of one — at least one colon, no triple
// colon, exactly one `::` if present, and ≤ 8 colon-separated groups.
const looksLikeIPv6 = (value: string): boolean => {
  if (!IPV6_BARE_RE.test(value)) return false
  if (!value.includes(':')) return false
  if (value.includes(':::')) return false
  // Count occurrences of `::` (compression). At most one allowed.
  const dblColon = value.match(/::/g)
  if (dblColon && dblColon.length > 1) return false
  // Split groups; the empty strings produced by `::` are fine.
  const groups = value.split(':')
  // After splitting, max 8 groups (or 9 when `::` introduces an empty
  // segment at start/end). Reject obvious overlength.
  if (groups.length > 9) return false
  for (const g of groups) {
    if (g.length > 4) return false
  }
  return true
}

// ─── Hostname ───────────────────────────────────────────────────────────────
// RFC 1123 form: labels are 1-63 chars of letters/digits/hyphens, can't
// start or end with hyphen, total length ≤ 253 chars, ≥ 2 labels (we
// reject single-label names like `localhost` to push operators toward
// the explicit `localhost` macro).
const HOSTNAME_LABEL_RE = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/

const isHostname = (value: string): boolean => {
  if (value.length > 253) return false
  // Strip a trailing dot so `example.com.` and `example.com` are both OK.
  const v = value.endsWith('.') ? value.slice(0, -1) : value
  if (v.length === 0) return false
  const labels = v.split('.')
  if (labels.length < 2) return false
  if (!labels.every((l) => HOSTNAME_LABEL_RE.test(l))) return false
  // Reject names that are purely numeric (e.g. `256.0.0.1`). A real
  // hostname's TLD per RFC 3696 must include at least one letter, so
  // requiring any letter anywhere is a strict-enough proxy that also
  // rules out "looks like a broken IPv4" inputs that the regex above
  // already let through to this point.
  if (!/[A-Za-z]/.test(v)) return false
  return true
}

/**
 * Validate a single line. Exposed for direct use when the consumer
 * doesn't need a full multi-line parse (e.g. a form-item rule that
 * checks just the last-typed value).
 */
export function parseAclLine(raw: string, lineNumber: number): AclLineResult {
  const trimmed = raw.trim()
  if (trimmed === '') {
    return { lineNumber, raw, kind: 'empty', negated: false, error: '' }
  }
  if (trimmed.startsWith('#') || trimmed.startsWith('//')) {
    return { lineNumber, raw, kind: 'comment', negated: false, error: '' }
  }

  // Strip BIND negation prefix. The `!` is structural, not part of
  // the value — peel it off once so the rest of the matchers don't
  // need to know about it.
  let value = trimmed
  let negated = false
  if (value.startsWith('!')) {
    negated = true
    value = value.slice(1).trim()
    if (value === '') {
      return {
        lineNumber,
        raw,
        kind: null,
        negated: false,
        error: 'negation prefix "!" must be followed by an address',
      }
    }
  }

  const lower = value.toLowerCase()
  if (ACL_MACROS.has(lower)) {
    return { lineNumber, raw, kind: 'macro', negated, error: '' }
  }

  if (IPV4_CIDR_RE.test(value)) {
    return { lineNumber, raw, kind: 'ipv4-cidr', negated, error: '' }
  }
  if (IPV4_RE.test(value)) {
    return { lineNumber, raw, kind: 'ipv4', negated, error: '' }
  }
  if (IPV6_CIDR_RE.test(value)) {
    const ipPart = value.split('/')[0]
    if (looksLikeIPv6(ipPart)) {
      return { lineNumber, raw, kind: 'ipv6-cidr', negated, error: '' }
    }
  }
  if (looksLikeIPv6(value)) {
    return { lineNumber, raw, kind: 'ipv6', negated, error: '' }
  }
  if (isHostname(value)) {
    return { lineNumber, raw, kind: 'hostname', negated, error: '' }
  }

  return {
    lineNumber,
    raw,
    kind: null,
    negated: false,
    error: `不是合法的 IP / CIDR / 主机名 / 宏: "${value}"`,
  }
}

/**
 * Parse a multi-line ACL textarea value.
 *
 * `\r\n`, `\n`, and `\r` are all accepted as line separators so we
 * tolerate paste from any OS without normalising up front.
 */
export function parseAcl(text: string): AclParseSummary {
  if (!text) {
    return { lines: [], errors: [], validEntries: 0 }
  }
  const rawLines = text.split(/\r\n|\r|\n/)
  const lines: AclLineResult[] = rawLines.map((raw, idx) =>
    parseAclLine(raw, idx + 1),
  )
  const errors = lines.filter((l) => l.error !== '')
  const validEntries = lines.filter(
    (l) => l.kind !== null && l.kind !== 'empty' && l.kind !== 'comment',
  ).length
  return { lines, errors, validEntries }
}
