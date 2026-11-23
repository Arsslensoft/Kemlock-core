// Fails when a package pub resolves for this one, a dependency, a development tool or one of
// theirs, has no licence file, a licence this script cannot tell, or one that is not on the list
// below, which is what a GPL-3.0-or-later project may build with and ship. The development tools
// count: they build and test the package. For the Checks workflow's Licences job
// (CONTRIBUTING.md); run it, after `dart pub get`, as `node .github/scripts/check-licences.mjs`.
//
// The packages are the ones in .dart_tool/package_config.json, which `dart pub get` writes from
// pubspec.lock. Every licence file of a package is read: each file at the top of its folder whose
// name starts with LICENSE, LICENCE, COPYING or NOTICE (any case, any extension: LICENSE-MIT,
// LICENSE-other.md), and every file under a top-level licenses/ or licences/ folder. The text of
// each is matched against the characteristic wording of the licences below (HTML is stripped of its
// tags first). A package's licence is all of what its files hold (`Apache-2.0 AND MIT`), and every
// one has to be on the list. A NOTICE file with no licence text in it is skipped; any other file
// the script cannot tell fails. Each package is reported as a direct dependency, a dev dependency
// or a transitive one, from pubspec.lock's `dependency` field.
//
// A package whose licence file is missing, or that this script cannot tell, is named in
// licence-exceptions.json (name@version: its licence as an SPDX expression and why) after a person
// has read its licence. An exception for a package that is no longer resolved fails, so that the
// file holds only what is needed. `WITH` takes only the exceptions listed below.
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))))

/** What GPL-3.0-or-later software may use and ship alongside its own code. */
const allowed = new Set(
  [
    '0BSD',
    'Apache-2.0',
    'BlueOak-1.0.0',
    'BSD-2-Clause',
    'BSD-3-Clause',
    'CC-BY-4.0',
    'CC0-1.0',
    'GPL-2.0-or-later',
    'GPL-3.0-only',
    'GPL-3.0-or-later',
    'ISC',
    'LGPL-2.1-or-later',
    'LGPL-3.0-only',
    'LGPL-3.0-or-later',
    'MIT',
    'MPL-2.0',
    'Python-2.0',
    'Unlicense',
    'Zlib',
  ].map((id) => id.toLowerCase()),
)

/** The exceptions that make a licence no stricter for what is built with it. */
const allowedExceptions = new Set(
  [
    'Autoconf-exception-3.0',
    'Bison-exception-2.2',
    'Classpath-exception-2.0',
    'GCC-exception-3.1',
    'LLVM-exception',
  ].map((id) => id.toLowerCase()),
)

/** The files at the top of a package's folder that are read as licence files, or the notice beside them. */
const licenceFileName = /^(licen[cs]e|copying|notice)/i

/** The folders at the top of a package's folder whose files are all read as licence files. */
const licenceFolderName = /^licen[cs]es$/i

/** A licence id as the list spells it: `GPL-2.0+` is `GPL-2.0-or-later`. */
const normalise = (id) => {
  const lower = id.toLowerCase()
  return lower.endsWith('+') ? `${lower.slice(0, -1)}-or-later` : lower
}

/** Splits an SPDX expression into its words and parentheses. */
const tokenize = (expression) => expression.match(/\(|\)|[^\s()]+/g) ?? []

/** Whether the SPDX expression [expression] can be satisfied with the allowed licences. */
function isAllowed(expression) {
  const tokens = tokenize(expression)
  let at = 0
  const peek = () => tokens[at]?.toUpperCase()

  function primary() {
    const token = tokens[at++]
    if (token === undefined) throw new Error('the expression ends too soon')
    if (token === '(') {
      const value = or()
      if (tokens[at++] !== ')') throw new Error('a parenthesis is not closed')
      return value
    }
    if (token === ')' || ['AND', 'OR', 'WITH'].includes(token.toUpperCase())) {
      throw new Error(`unexpected ${token}`)
    }
    let ok = allowed.has(normalise(token))
    if (peek() === 'WITH') {
      at++
      const exception = tokens[at++]
      if (exception === undefined) throw new Error('WITH names no exception')
      ok = ok && allowedExceptions.has(exception.toLowerCase())
    }
    return ok
  }
  function and() {
    let value = primary()
    while (peek() === 'AND') {
      at++
      const next = primary()
      value = value && next
    }
    return value
  }
  function or() {
    let value = and()
    while (peek() === 'OR') {
      at++
      const next = and()
      value = value || next
    }
    return value
  }

  const value = or()
  if (at < tokens.length) throw new Error(`unexpected ${tokens[at]}`)
  return value
}

/**
 * The SPDX ids of the licences a licence file's text holds, told by their characteristic wording.
 * An empty list is a text this script does not know. A GPL, LGPL or AGPL text that is not a short
 * notice naming "any later version" is the `-only` kind, which the list takes for GPL-3.0 and
 * LGPL-3.0 and not for GPL-2.0, LGPL-2.1 or AGPL, so that a person decides those.
 */
function classify(raw) {
  const text = raw
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/\s+/g, ' ')
    .toLowerCase()
  const has = (pattern) => (typeof pattern === 'string' ? text.includes(pattern) : pattern.test(text))
  const found = []

  if (has('apache license') && has('version 2.0, january 2004')) found.push('Apache-2.0')
  if (has(/mozilla public license,? (version|v\.?) ?2\.0/)) found.push('MPL-2.0')
  if (has('this is free and unencumbered software released into the public domain')) found.push('Unlicense')
  if (has(/cc0 1\.0 universal|creative commons zero/)) found.push('CC0-1.0')
  if (has(/this software is provided ['"`]?as-is['"`]?, without any express or implied warranty/) && has('altered source versions must be plainly marked')) {
    found.push('Zlib')
  }
  if (has('permission is hereby granted, free of charge, to any person obtaining a copy')) found.push('MIT')
  if (has('permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted')) {
    found.push(has('provided that the above copyright notice and this permission notice appear in all copies') ? 'ISC' : '0BSD')
  }
  if (has('redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met')) {
    if (has('all advertising materials mentioning features')) found.push('BSD-4-Clause')
    else if (has(/neither the name of|may be used to endorse or promote products|may not be used to endorse or promote products/)) {
      found.push('BSD-3-Clause')
    } else found.push('BSD-2-Clause')
  }

  // The GPL family. A full text names the others (the GPL's ends by pointing to the LGPL), so the
  // title that comes first is the licence. "Or any later version" only counts in a short notice: a
  // full text holds it in its "how to apply" part whatever the licence's own terms are
  const titles = [
    ['lgpl', 'gnu lesser general public license'],
    ['lgpl', 'gnu library general public license'],
    ['agpl', 'gnu affero general public license'],
    ['gpl', 'gnu general public license'],
  ]
    .map(([family, title]) => [family, text.indexOf(title)])
    .filter(([, at]) => at >= 0)
    .sort((a, b) => a[1] - b[1])
  // A full text starts with its title; a short notice names the licence it is under. A longer text
  // that only mentions a GPL somewhere (the MPL-2.0's secondary licences) is not one
  if (titles.length && (titles[0][1] < 400 || text.length < 4000)) {
    const later = text.length < 4000 && has(/or (\(at your option\) )?any later version/)
    const suffix = (only) => (later ? '-or-later' : only)
    const family = titles[0][0]
    if (family === 'lgpl') {
      if (has('version 3, 29 june 2007')) found.push(`LGPL-3.0${suffix('-only')}`)
      else if (has('version 2.1, february 1999')) found.push(`LGPL-2.1${suffix('-only')}`)
      else if (has('version 2, june 1991')) found.push(`LGPL-2.0${suffix('-only')}`)
      else found.push('LGPL')
    } else if (family === 'agpl') {
      found.push(`AGPL-3.0${suffix('-only')}`)
    } else if (has('version 3, 29 june 2007')) {
      found.push(`GPL-3.0${suffix('-only')}`)
    } else if (has('version 2, june 1991')) {
      found.push(`GPL-2.0${suffix('-only')}`)
    } else found.push('GPL')
  }
  return found
}

/**
 * The licence files a package folder holds, as [{ file, text, notice }]: the files at its top whose
 * names start with LICENSE, LICENCE, COPYING or NOTICE, and every file under a top-level licenses/
 * or licences/ folder, in name order.
 */
function licencesIn(dir) {
  if (!existsSync(dir)) return undefined
  const files = []
  const read = (path, file, notice) => {
    let text = readFileSync(path, 'utf8')
    if (/\.html?$/i.test(file)) text = text.replace(/<[^>]*>/g, ' ')
    files.push({ file, text, notice })
  }
  const walk = (folder, prefix) => {
    for (const entry of readdirSync(folder, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isDirectory()) walk(join(folder, entry.name), `${prefix}${entry.name}/`)
      else if (entry.isFile()) read(join(folder, entry.name), `${prefix}${entry.name}`, false)
    }
  }
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.isFile() && licenceFileName.test(entry.name)) read(join(dir, entry.name), entry.name, /^notice/i.test(entry.name))
    else if (entry.isDirectory() && licenceFolderName.test(entry.name)) walk(join(dir, entry.name), `${entry.name}/`)
  }
  return files
}

/** What pubspec.lock says of each package: { kind, version, source }, kind being direct, dev or transitive. */
function readLock(path) {
  const kinds = { 'direct main': 'direct', 'direct overridden': 'direct', 'direct dev': 'dev', transitive: 'transitive' }
  const packages = new Map()
  let inPackages = false
  let current
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    if (/^\S/.test(line)) inPackages = line.startsWith('packages:')
    if (!inPackages) continue
    const name = /^ {2}([^\s:]+):\s*$/.exec(line)
    if (name) {
      current = { kind: 'transitive', version: '', source: '' }
      packages.set(name[1], current)
      continue
    }
    const field = /^ {4}(dependency|version|source):\s*"?([^"]*?)"?\s*$/.exec(line)
    if (field && current) {
      if (field[1] === 'dependency') current.kind = kinds[field[2]] ?? field[2]
      else current[field[1]] = field[2]
    }
  }
  return packages
}

const pubspecName = /^name:\s*(\S+)/m.exec(readFileSync(join(root, 'pubspec.yaml'), 'utf8'))?.[1]
const lockFile = join(root, 'pubspec.lock')
const configFile = join(root, '.dart_tool', 'package_config.json')
const exceptionsFile = join(root, '.github', 'licence-exceptions.json')

let failures = 0
const fail = (message) => {
  failures++
  console.log(`::error title=Licences::${message.replace(/%/g, '%25').replace(/\n/g, '%0A')}`)
}

if (!existsSync(lockFile)) {
  fail('pubspec.lock is missing: commit it (dart pub get writes it)')
}
if (!existsSync(configFile)) {
  fail('.dart_tool/package_config.json is missing: run `dart pub get` first')
}
if (failures) process.exit(1)

const exceptions = existsSync(exceptionsFile) ? JSON.parse(readFileSync(exceptionsFile, 'utf8')) : {}
const lock = readLock(lockFile)
const config = JSON.parse(readFileSync(configFile, 'utf8'))
const base = pathToFileURL(join(root, '.dart_tool') + '/')

for (const [key, exception] of Object.entries(exceptions)) {
  let ok
  try {
    ok = isAllowed(exception.licence ?? '')
  } catch {
    ok = false
  }
  if (!ok) fail(`licence-exceptions.json: ${key} names a licence that is not on the list`)
  if (typeof exception.reason !== 'string' || !exception.reason.trim()) {
    fail(`licence-exceptions.json: ${key} has no reason`)
  }
}

const used = new Set()
const counts = new Map()
const count = (licence) => counts.set(licence, (counts.get(licence) ?? 0) + 1)

for (const pkg of config.packages ?? []) {
  if (pkg.name === pubspecName) continue
  const entry = lock.get(pkg.name)
  const kind = entry?.kind ?? '(not in pubspec.lock)'
  if (!entry) fail(`${pkg.name} is resolved but not in pubspec.lock: run \`dart pub get\` and commit pubspec.lock`)
  const id = `${pkg.name}@${entry?.version ?? '?'}`
  const exception = exceptions[id]
  if (exception) used.add(id)

  const dir = fileURLToPath(new URL(pkg.rootUri.endsWith('/') ? pkg.rootUri : `${pkg.rootUri}/`, base))
  const files = licencesIn(dir)
  let licence
  let from
  if (exception) {
    licence = exception.licence
    from = 'licence-exceptions.json'
  } else if (!files) {
    fail(`${id} (${kind}) is not downloaded at ${dir}: run \`dart pub get\``)
    continue
  } else if (!files.length) {
    count('(no licence file)')
    fail(`${id} (${kind}) has no licence file (LICENSE*, LICENCE*, COPYING* or licenses/): read its licence, then add it to licence-exceptions.json`)
    console.log(`  ${id}  ${kind}  (no licence file)`)
    continue
  } else {
    // Each file's licences; a notice with none is only a notice, any other file with none is a failure
    const ids = []
    const unknown = []
    for (const { file, text, notice } of files) {
      const found = classify(text)
      if (!found.length && !notice) unknown.push(file)
      for (const one of found) if (!ids.includes(one)) ids.push(one)
    }
    from = files.map(({ file }) => file).join(', ')
    if (unknown.length || !ids.length) {
      count('(unknown)')
      const which = unknown.length ? unknown.join(', ') : from
      fail(`${id} (${kind}) has licence file(s) (${which}) that this script cannot tell: read them, then add the package to licence-exceptions.json`)
      console.log(`  ${id}  ${kind}  ${from}  (unknown: ${which})`)
      continue
    }
    licence = ids.join(' AND ')
  }

  count(licence)
  console.log(`  ${id}  ${kind}  ${from}  ${licence}`)
  try {
    if (!isAllowed(licence)) {
      fail(`${id} (${kind}) is under ${licence}, which is not on the list of compatible licences`)
    }
  } catch (error) {
    fail(`${id} (${kind}) has "${licence}", not an SPDX expression (${error.message})`)
  }
}

for (const key of Object.keys(exceptions)) {
  if (!used.has(key)) {
    fail(`licence-exceptions.json names ${key}, which pub does not resolve: remove it`)
  }
}

console.log('')
for (const [licence, total] of [...counts].sort((a, b) => b[1] - a[1])) {
  console.log(`${String(total).padStart(5)}  ${licence}`)
}
if (failures) {
  console.log(`licences: ${failures} problem(s)`)
  process.exit(1)
}
console.log('licences: ok')
