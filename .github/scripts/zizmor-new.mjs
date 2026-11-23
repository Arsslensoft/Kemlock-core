// zizmor-new.mjs BASE.json HEAD.json: the workflow findings zizmor (--format json) makes on the
// change that it does not make on the branch the change starts from, for the Checks workflow's
// Security job. A finding is its rule, its file, its job (or top-level key) and what it points at
// (the expression itself where zizmor names one, else the text), counted, so that a step added or
// moved elsewhere, or another line of the same block changed, leaves an old finding old. Each new
// finding is an annotation on its line; the exit status is 1 when one is of medium severity or
// more. What main has already is a change of its own, not every pull request's.
import fs from 'node:fs'

const read = (file) => JSON.parse(fs.readFileSync(file, 'utf8').trim() || '[]')
const primary = (f) => f.locations.find((l) => l.symbolic.kind === 'Primary') ?? f.locations[0]
const fileOf = (l) => l.symbolic.key.Local?.verbatim_path ?? ''
const keyOf = (f) => {
  const l = primary(f)
  const route = l.symbolic.route.route.map((c) => c.Key ?? c.Index)
  const what = l.symbolic.feature_kind?.Subfeature?.fragment?.Raw ?? l.concrete.feature
  const text = what.replace(/\r\n/g, '\n').trim()
  return [f.ident, fileOf(l), route.slice(0, 2).join('.'), text].join('\0')
}
// A workflow command's value cannot hold a line break or a bare %
const escapes = { '%': '%25', '\r': '%0D', '\n': '%0A' }
const escape = (text) => String(text).replace(/[%\r\n]/g, (c) => escapes[c])

const before = new Map()
for (const f of read(process.argv[2])) before.set(keyOf(f), (before.get(keyOf(f)) ?? 0) + 1)
let added = 0
let severe = 0
for (const f of read(process.argv[3])) {
  const key = keyOf(f)
  if (before.get(key) > 0) {
    before.set(key, before.get(key) - 1)
    continue
  }
  added++
  const blocking = ['Medium', 'High'].includes(f.determinations.severity)
  if (blocking) severe++
  const l = primary(f)
  const where = `file=${fileOf(l)},line=${l.concrete.location.start_point.row + 1}`
  const what = `${f.desc} (${f.determinations.severity}): ${l.symbolic.annotation}. ${f.url}`
  const command = blocking ? 'error' : 'warning'
  console.log(`::${command} ${where},title=zizmor ${f.ident}::${escape(what)}`)
}
console.log(`zizmor: ${added} new finding(s), ${severe} of medium severity or more`)
process.exit(severe ? 1 : 0)
