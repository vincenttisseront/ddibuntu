import { describe, expect, it } from 'vitest'
import { classBody, classTest, keaClasses, normHex, normMatchMac, planWindowsClasses } from '../server/utils/dhcp-classes'
import { renderKea, KEA_DEFAULTS } from '../server/utils/render'

const ok = (o: any) => classBody.safeParse({ name: 'Cam', kind: 'vendor', match: 'AXIS', ...o })
describe('classes de clients DHCP', () => {
  it('option 43 et MAC normalisés', () => {
    expect(normHex('01:04-C0 a8:00:01')).toBe('0104c0a800 01'.replace(' ', '')); expect(normHex('0')).toBeNull(); expect(normHex('zz')).toBeNull(); expect(normHex('')).toBeNull()
    expect(normMatchMac('AA-BB-CC')).toBe('aa:bb:cc'); expect(normMatchMac('aabbccddeeff')).toBe('aa:bb:cc:dd:ee:ff'); expect(normMatchMac('aa:bb')).toBeNull()
  })
  it('validation : nom réservé, guillemets refusés, rejet sans options', () => {
    expect(ok({}).success).toBe(true); expect(ok({ name: 'DROP' }).success).toBe(false); expect(ok({ match: "a'b" }).success).toBe(false); expect(ok({ match: 'a\\b' }).success).toBe(false)
    expect(ok({ option43: 'xyz' }).success).toBe(false); expect(ok({ action: 'drop', option43: '01' }).success).toBe(false)
    expect(ok({ kind: 'mac', match: 'aa:bb:cc' }).data?.match).toBe('aa:bb:cc'); expect(ok({ kind: 'mac', match: 'nope' }).success).toBe(false)
    expect(ok({ option43: '01:02' }).data).toMatchObject({ name: 'cam', option43: '0102' })
  })
  it('expressions Kea', () => {
    expect(classTest('vendor', 'AXIS')).toBe("substring(option[60].text,0,4) == 'AXIS'"); expect(classTest('user', 'x')).toBe("substring(option[77].text,0,1) == 'x'")
    expect(classTest('mac', 'aa:bb:cc')).toBe('substring(pkt4.mac,0,3) == 0xaabbcc'); expect(classTest('mac', 'aa:bb:cc:dd:ee:ff')).toBe('pkt4.mac == 0xaabbccddeeff')
  })
  it('client-classes : options, DROP unique, désactivées ignorées ; rendu Kea', () => {
    const rows: any[] = [
      { name: 'cam', kind: 'vendor', match: 'AXIS', action: 'assign', option43: '0104c0a80001', tftp_server: null, boot_file: 'pxe.0', enabled: true },
      { name: 'off', kind: 'user', match: 'z', action: 'assign', option43: null, tftp_server: null, boot_file: null, enabled: false },
      { name: 'd1', kind: 'mac', match: 'aa:bb:cc', action: 'drop', option43: null, tftp_server: null, boot_file: null, enabled: true },
      { name: 'd2', kind: 'mac', match: 'aa:bb:cc:dd:ee:ff', action: 'drop', option43: null, tftp_server: null, boot_file: null, enabled: true }]
    const k = keaClasses(rows)
    expect(k.map((x) => x.name)).toEqual(['cam', 'DROP'])
    expect(k[0]['option-data']).toEqual([{ code: 43, space: 'dhcp4', 'csv-format': false, data: '0104c0a80001' }, { name: 'boot-file-name', data: 'pxe.0' }])
    expect(k[1].test).toBe('(substring(pkt4.mac,0,3) == 0xaabbcc) or (pkt4.mac == 0xaabbccddeeff)')
    expect(JSON.parse(renderKea(KEA_DEFAULTS, [], k)).Dhcp4['client-classes']).toHaveLength(2)
    expect(JSON.parse(renderKea(KEA_DEFAULTS, [])).Dhcp4['client-classes']).toBeUndefined()
  })
  it('import Windows : classes décodées, filtres « refuser » en rejet MAC, « autoriser » et données illisibles ignorés', () => {
    const X = `<DHCPServer><IPv4><Classes><Class><Name>Axis Cams</Name><Type>Vendor</Type><Data>41584953</Data></Class><Class><Name>Binaire</Name><Type>User</Type><Data>00ff01</Data></Class></Classes>
      <Filters><Filter><List>Deny</List><MacAddress>AA-BB-CC-DD-EE-FF</MacAddress></Filter><Filter><List>Deny</List><MacAddress>11-22-33-*</MacAddress></Filter><Filter><List>Allow</List><MacAddress>99-99-99-99-99-99</MacAddress></Filter></Filters></IPv4></DHCPServer>`
    const p = planWindowsClasses(X, new Set(['axis-cams']))
    const by = Object.fromEntries(p.items.map((i) => [i.name, i]))
    expect(by['axis-cams']).toMatchObject({ status: 'exists', kind: 'vendor', match: 'AXIS' }); expect(by['binaire']).toMatchObject({ status: 'skip', reason: 'class_data' })
    expect(by['deny-aa-bb-cc-dd-ee-ff']).toMatchObject({ status: 'create', action: 'drop', match: 'aa:bb:cc:dd:ee:ff' }); expect(by['deny-11-22-33']).toMatchObject({ status: 'create', match: '11:22:33' })
    expect(p.items.find((i) => i.reason === 'allow_list')).toBeTruthy()
    expect(planWindowsClasses('<x', new Set()).errors).toEqual(['dhcp_xml_invalid']); expect(planWindowsClasses('<a/>', new Set()).errors).toEqual(['dhcp_no_ipv4'])
  })
})
