// Descripteur de sécurité d'une GPO (0.20.0) : « filtrage de sécurité » par groupe. Par défaut « Utilisateurs authentifiés » a le droit d'appliquer la stratégie
// (droit étendu « Apply Group Policy ») ; on le retire et on le donne au seul groupe choisi. « Utilisateurs authentifiés » garde la lecture, indispensable aux postes
// pour lire la GPO (correctif MS16-072). Seule la DACL est lue et réécrite (contrôle LDAP SD_FLAGS = 4), jamais le propriétaire ni la SACL.
export const APPLY_GROUP_POLICY = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
/** S-1-5-11 (Utilisateurs authentifiés), au format binaire. */
export const AUTHENTICATED_USERS = Buffer.from([1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0])
const ACCESS_ALLOWED_OBJECT = 5, OBJECT_TYPE_PRESENT = 1, INHERITED_PRESENT = 2, INHERITED_ACE = 0x10, CONTAINER_INHERIT = 0x02, CONTROL_ACCESS = 0x100

/** GUID texte → octets Windows (les trois premiers groupes en petit-boutiste). */
export function guidBytes(g: string): Buffer {
  const h = g.replace(/-/g, ''), b = Buffer.from(h, 'hex')
  if (b.length !== 16) throw new Error('guid')
  return Buffer.concat([Buffer.from(b.subarray(0, 4)).reverse(), Buffer.from(b.subarray(4, 6)).reverse(), Buffer.from(b.subarray(6, 8)).reverse(), b.subarray(8)])
}
const APPLY = guidBytes(APPLY_GROUP_POLICY)

/** Dernier élément (RID) d'un SID binaire. */
export const ridOf = (sid: Buffer): number => sid.readUInt32LE(sid.length - 4)

interface Ace { raw: Buffer; type: number; flags: number }
/** L'ACE est-elle « autoriser Apply Group Policy » pour ce SID ? */
function appliesTo(a: Ace, sid: Buffer): boolean {
  if (a.type !== ACCESS_ALLOWED_OBJECT || a.raw.length < 12) return false
  const of = a.raw.readUInt32LE(8)
  if (!(of & OBJECT_TYPE_PRESENT) || a.raw.length < 28) return false
  if (!a.raw.subarray(12, 28).equals(APPLY)) return false
  const start = 12 + 16 + (of & INHERITED_PRESENT ? 16 : 0)
  return a.raw.subarray(start).equals(sid)
}

/** Retourne la DACL modifiée : le droit d'appliquer retiré à « Utilisateurs authentifiés », donné au groupe. `changed` = faux si elle était déjà ainsi. */
export function filterGpoAcl(sd: Buffer, groupSid: Buffer): { sd: Buffer; changed: boolean } {
  if (sd.length < 28 || sd[0] !== 1) throw new Error('sd')
  const owner = sd.readUInt32LE(4), group = sd.readUInt32LE(8), sacl = sd.readUInt32LE(12), dacl = sd.readUInt32LE(16)
  if (owner || group || sacl || !dacl || dacl + 8 > sd.length) throw new Error('sd')   // uniquement une DACL (contrôle SD_FLAGS = 4)
  const size = sd.readUInt16LE(dacl + 2), count = sd.readUInt16LE(dacl + 4)
  if (dacl + size > sd.length) throw new Error('sd')
  const aces: Ace[] = []
  for (let p = dacl + 8, n = 0; n < count; n++) {
    if (p + 8 > dacl + size) throw new Error('sd')
    const len = sd.readUInt16LE(p + 2)
    if (len < 8 || p + len > dacl + size) throw new Error('sd')
    aces.push({ raw: sd.subarray(p, p + len), type: sd[p]!, flags: sd[p + 1]! }); p += len
  }
  const kept = aces.filter((a) => !appliesTo(a, AUTHENTICATED_USERS))
  let changed = kept.length !== aces.length
  if (!kept.some((a) => appliesTo(a, groupSid))) {
    const head = Buffer.alloc(12); head[0] = ACCESS_ALLOWED_OBJECT; head[1] = CONTAINER_INHERIT; head.writeUInt16LE(12 + 16 + groupSid.length, 2); head.writeUInt32LE(CONTROL_ACCESS, 4); head.writeUInt32LE(OBJECT_TYPE_PRESENT, 8)
    const ace: Ace = { raw: Buffer.concat([head, APPLY, groupSid]), type: ACCESS_ALLOWED_OBJECT, flags: CONTAINER_INHERIT }
    const at = kept.findIndex((a) => a.flags & INHERITED_ACE)   // avant les ACE héritées : les explicites d'abord
    kept.splice(at < 0 ? kept.length : at, 0, ace); changed = true
  }
  const body = Buffer.concat(kept.map((a) => a.raw))
  const acl = Buffer.alloc(8); acl[0] = sd[dacl]!; acl.writeUInt16LE(8 + body.length, 2); acl.writeUInt16LE(kept.length, 4)
  return { sd: Buffer.concat([sd.subarray(0, dacl), acl, body]), changed }
}
