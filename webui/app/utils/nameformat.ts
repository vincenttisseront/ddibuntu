// Déduit le « format de nom généré » de la règle de nommage : « srv-### » → « srv-{o4:3} », « vmdmz-* » → « vmdmz-{o4:3} », « pc-?? » → « pc-{o4:2} ».
export function deriveNameFormat(pattern: string): string {
  const p = String(pattern ?? '').trim()
  if (!p) return ''
  return p.replace(/#+|\?+|\*+/g, (m) => (m[0] === '*' ? '{o4:3}' : `{o4:${m.length}}`))
}
