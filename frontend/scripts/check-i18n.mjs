#!/usr/bin/env node
// scripts/check-i18n.mjs
//
// Scans the locale files (zh-CN.ts / en-US.ts) versus actual usage in
// .vue / .ts source, then reports:
//
//   1. orphan keys     — declared in zh-CN but never referenced anywhere
//   2. missing keys    — referenced in source but absent from zh-CN
//   3. drift between zh-CN and en-US (one has a key, the other doesn't)
//
// The script is heuristic, not a parser. It treats the locale file as
// JS source, evaluates it via dynamic import, and walks the resulting
// object to flatten it into dot-paths ("user.kickAllBtn" etc). Source
// scanning matches three patterns that cover ~all of our codebase:
//
//     $t('foo.bar')         | t('foo.bar')          | i18n.global.t('foo.bar')
//
// Limitations: keys built dynamically (`$t('foo.' + suffix)`) are
// invisible to the scanner and may be flagged as orphans. Add them to
// IGNORE_PREFIXES below when this happens.
//
// Usage:
//
//   node scripts/check-i18n.mjs           # report only
//   node scripts/check-i18n.mjs --json    # machine-readable
//
// Exit codes:
//   0 — no drift, no missing, no orphans
//   1 — issues found
//   2 — script error (couldn't load locale)

import { readdir, readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, join, relative } from 'node:path'

const __filename = fileURLToPath(import.meta.url)
const __dirname  = dirname(__filename)
const ROOT       = join(__dirname, '..')
const SRC_DIR    = join(ROOT, 'src')

// Add prefixes here when a runtime-built key is mistakenly flagged as
// orphan (e.g. `$t('menu.' + route.meta.titleKey)` produces dynamic
// `menu.*` paths that we can't statically resolve).
const IGNORE_PREFIXES = [
  'menu.',           // route titles built from route.meta.titleKey
  'common.',         // tiny shared strings; hard to track every callsite
]

// File extensions we scan for $t / t() calls.
const SOURCE_EXTS = new Set(['.vue', '.ts', '.tsx', '.js', '.jsx'])

const args  = new Set(process.argv.slice(2))
const asJson = args.has('--json')

async function loadLocale(file) {
  // The locale file is plain TS exporting a default object literal.
  // Strip the `export default` wrapper and `as const` / `satisfies`
  // suffix, then evaluate with new Function so we don't need a TS
  // compiler in the dev loop.
  const raw = await readFile(file, 'utf8')
  const m = raw.match(/export\s+default\s+([\s\S]+?)\s*(?:as\s+const|satisfies\s+\w+)?\s*$/)
  if (!m) throw new Error(`could not extract default export from ${file}`)
  // `eval` would be marginally simpler, but Function() at least scopes
  // the badness to one expression.
  // eslint-disable-next-line no-new-func
  return Function(`"use strict"; return (${m[1]});`)()
}

function flatten(obj, prefix = '', out = new Set()) {
  for (const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, path, out)
    else out.add(path)
  }
  return out
}

async function* walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  for (const e of entries) {
    const p = join(dir, e.name)
    if (e.isDirectory()) {
      if (e.name === 'i18n' || e.name === 'node_modules') continue
      yield* walk(p)
    } else if (SOURCE_EXTS.has(p.slice(p.lastIndexOf('.')))) {
      yield p
    }
  }
}

// Match: $t('x.y')  /  t('x.y')  /  i18n.global.t('x.y') — single OR
// double quotes, key chars include letters/digits/dot/underscore.
const KEY_RE = /(?:\$t|[\s.{(=,]t|i18n\.global\.t)\s*\(\s*['"]([\w.]+?)['"]/g

async function collectUsedKeys() {
  const used = new Set()
  for await (const file of walk(SRC_DIR)) {
    const raw = await readFile(file, 'utf8')
    let m
    while ((m = KEY_RE.exec(raw)) !== null) used.add(m[1])
  }
  return used
}

const isIgnored = (key) => IGNORE_PREFIXES.some(p => key.startsWith(p))

async function main() {
  const zhFile = join(SRC_DIR, 'i18n', 'zh-CN.ts')
  const enFile = join(SRC_DIR, 'i18n', 'en-US.ts')

  const [zh, en] = await Promise.all([
    loadLocale(zhFile),
    loadLocale(enFile),
  ])

  const zhKeys = flatten(zh)
  const enKeys = flatten(en)
  const used   = await collectUsedKeys()

  const orphans = [...zhKeys].filter(k => !used.has(k) && !isIgnored(k)).sort()
  const missing = [...used].filter(k => !zhKeys.has(k) && !isIgnored(k)).sort()
  const onlyZh  = [...zhKeys].filter(k => !enKeys.has(k)).sort()
  const onlyEn  = [...enKeys].filter(k => !zhKeys.has(k)).sort()

  const report = {
    counts: {
      zhKeys: zhKeys.size,
      enKeys: enKeys.size,
      used:   used.size,
      orphans: orphans.length,
      missing: missing.length,
      driftZhOnly: onlyZh.length,
      driftEnOnly: onlyEn.length,
    },
    orphans,
    missing,
    driftZhOnly: onlyZh,
    driftEnOnly: onlyEn,
  }

  if (asJson) {
    console.log(JSON.stringify(report, null, 2))
  } else {
    const f = (label, arr) => {
      console.log(`\n=== ${label} (${arr.length}) ===`)
      arr.slice(0, 50).forEach(k => console.log('  ' + k))
      if (arr.length > 50) console.log(`  … (${arr.length - 50} more, use --json)`)
    }
    console.log('i18n key audit')
    console.log(`  zh-CN keys: ${zhKeys.size}`)
    console.log(`  en-US keys: ${enKeys.size}`)
    console.log(`  source uses: ${used.size}`)
    if (orphans.length) f('orphans (declared but unused)', orphans)
    if (missing.length) f('missing (used but undeclared in zh-CN)', missing)
    if (onlyZh.length)  f('drift: only in zh-CN', onlyZh)
    if (onlyEn.length)  f('drift: only in en-US', onlyEn)
    if (!orphans.length && !missing.length && !onlyZh.length && !onlyEn.length) {
      console.log('  ✓ no issues')
    }
  }

  const issues = orphans.length + missing.length + onlyZh.length + onlyEn.length
  process.exit(issues > 0 ? 1 : 0)
}

main().catch(e => {
  console.error('check-i18n failed:', e)
  process.exit(2)
})
