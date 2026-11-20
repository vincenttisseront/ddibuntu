// Script PowerShell de mise en place de la GPO d'enrôlement (0.18.3), généré par la console. À lancer une fois par un administrateur du domaine
// (contrôleur de domaine, ou poste avec RSAT : modules GroupPolicy et ActiveDirectory). Il ne contient aucune valeur interpolée : seuls des fichiers
// sont embarqués (en base64) et leurs noms sont fixes ou dérivés d'une empreinte hexadécimale.
import { X509Certificate } from 'node:crypto'

/** Fichiers déposés dans le dossier de démarrage de la GPO : nom → contenu. */
export type GpoFiles = Record<string, Buffer>

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const BOM = Buffer.from([0xef, 0xbb, 0xbf])

/** Lance, à chaque démarrage du poste : ajoute les autorités à confiance aux racines de l'ordinateur, puis installe la tâche d'enrôlement. */
const STARTUP = String.raw`# DDI-Buntu : script de demarrage (GPO). Execute en SYSTEM au demarrage de l'ordinateur.
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dir = Join-Path $env:ProgramFiles 'DDI-Buntu'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
function Write-Log([string]$m) { Add-Content -Path (Join-Path $dir 'enroll.log') -Value ('{0:s} demarrage : {1}' -f (Get-Date), $m) }
foreach ($f in Get-ChildItem -Path $here -Filter 'anchor-*.cer') {
  try {
    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $f.FullName
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList 'Root', 'LocalMachine'
    $s.Open('ReadWrite')
    if ($s.Certificates.Find('FindByThumbprint', $c.Thumbprint, $false).Count -eq 0) { $s.Add($c); Write-Log ('autorite ajoutee aux racines de confiance : ' + $c.Thumbprint) }
    $s.Close()
  } catch { Write-Log ('autorite ' + $f.Name + ' : ' + $_.Exception.Message) }
}
& (Join-Path $here 'enroll.ps1') -Install
`

const TEMPLATE = String.raw`<#
 DDI-Buntu : mise en place de la GPO d'enrolement des certificats de poste.
 Genere par la console du DDI. A lancer UNE FOIS, avec un compte administrateur du domaine, sur un controleur de domaine
 ou un poste d'administration disposant des outils RSAT (modules GroupPolicy et ActiveDirectory).

   .\deploy-gpo.ps1 -Ou 'OU=Postes,DC=example,DC=org' -WhatIf    : montre ce qui serait fait, sans rien modifier
   .\deploy-gpo.ps1 -Ou 'OU=Postes,DC=example,DC=org'            : cree la GPO, y depose les fichiers, la lie a l'unite d'organisation

 Ce script peut etre relance sans danger : il ne refait que ce qui manque. Il ne modifie que la GPO qu'il cree (ou retrouve par son nom).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory = $true)][string]$Ou,
  [string]$GpoName = 'DDI-Buntu enrolement'
)
$ErrorActionPreference = 'Stop'
$Files = [ordered]@{
__FILES__
}
$StartupScript = 'ddi-demarrage.ps1'
$CseScripts = '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}'
$ToolScripts = '{40B6664F-4972-11D1-A7CA-0000F87571E3}'

Import-Module GroupPolicy
Import-Module ActiveDirectory
$domain = Get-ADDomain
$dns = $domain.DNSRoot
$pdc = $domain.PDCEmulator
$null = Get-ADOrganizationalUnit -Identity $Ou -Server $pdc   # echoue si l'unite d'organisation n'existe pas

$gpo = Get-GPO -Name $GpoName -Server $pdc -ErrorAction SilentlyContinue
if (-not $gpo) {
  if (-not $PSCmdlet.ShouldProcess($GpoName, 'creer la GPO')) {
    Write-Host ('Simulation : la GPO serait creee, puis ' + ($Files.Keys -join ', ') + ' deposes dans son dossier de demarrage, le script declare, et la GPO liee a ' + $Ou + '.')
    return
  }
  $gpo = New-GPO -Name $GpoName -Server $pdc -Comment 'DDI-Buntu : enrolement des certificats de poste'
  Write-Host ('GPO creee : ' + $GpoName)
}
$guid = '{' + $gpo.Id.ToString().ToUpper() + '}'
$policy = "\\$pdc\SYSVOL\$dns\Policies\$guid"
$startup = Join-Path $policy 'Machine\Scripts\Startup'
$changed = $false

# 1. fichiers dans le dossier de demarrage de la GPO
if ($PSCmdlet.ShouldProcess($startup, 'deposer les fichiers')) { New-Item -ItemType Directory -Force -Path $startup | Out-Null }
foreach ($name in $Files.Keys) {
  $bytes = [Convert]::FromBase64String($Files[$name])
  $target = Join-Path $startup $name
  $same = (Test-Path -LiteralPath $target) -and ([Convert]::ToBase64String([IO.File]::ReadAllBytes($target)) -eq $Files[$name])
  if (-not $same -and $PSCmdlet.ShouldProcess($target, 'ecrire')) { [IO.File]::WriteAllBytes($target, $bytes); $changed = $true; Write-Host ('ecrit : ' + $name) }
}

# 2. declaration du script de demarrage (onglet "Scripts", comme dans l'editeur de GPO)
$ini = Join-Path $policy 'Machine\Scripts\scripts.ini'
$cmdLine = 'powershell.exe'
$params = '-NoProfile -ExecutionPolicy Bypass -File "\\' + $dns + '\SYSVOL\' + $dns + '\Policies\' + $guid + '\Machine\Scripts\Startup\' + $StartupScript + '"'
$crlf = [string][char]13 + [string][char]10
$lf = [string][char]10
$wanted = '[Startup]' + $crlf + '0CmdLine=' + $cmdLine + $crlf + '0Parameters=' + $params + $crlf
$current = ''
if (Test-Path -LiteralPath $ini) { $current = [IO.File]::ReadAllText($ini) }
if ($current.Replace($crlf, $lf).Trim() -ne $wanted.Replace($crlf, $lf).Trim()) {
  if ($current.Trim().Length -gt 0 -and $current -notlike "*$StartupScript*") {
    throw "scripts.ini existe deja avec d'autres scripts : ajoutez-y a la main powershell.exe avec le parametre ci-dessus, ou utilisez une autre GPO (-GpoName)."
  }
  if ($PSCmdlet.ShouldProcess($ini, 'ecrire')) { [IO.File]::WriteAllText($ini, $wanted, [Text.Encoding]::Unicode); $changed = $true; Write-Host 'scripts.ini ecrit' }
}

# 3. l'extension "scripts" doit etre declaree sur la GPO, et sa version augmentee pour que les postes la relisent
$obj = Get-ADObject -Identity $gpo.Path -Server $pdc -Properties gPCMachineExtensionNames, versionNumber
$groups = New-Object System.Collections.Generic.List[string]
foreach ($m in [regex]::Matches([string]$obj.gPCMachineExtensionNames, '\[[^\]]*\]')) { $groups.Add($m.Value) }
$hasTool = $false
for ($i = 0; $i -lt $groups.Count; $i++) {
  if ($groups[$i].StartsWith('[' + $CseScripts)) {
    if ($groups[$i].Contains($ToolScripts)) { $hasTool = $true } else { $groups[$i] = $groups[$i].TrimEnd(']') + $ToolScripts + ']'; $hasTool = $true; $changed = $true }
  }
}
if (-not $hasTool) { $groups.Add('[' + $CseScripts + $ToolScripts + ']'); $changed = $true }
$groups.Sort([StringComparer]::Ordinal)
$ext = -join $groups
if ($changed -and $PSCmdlet.ShouldProcess($gpo.Path, 'declarer l''extension et augmenter la version')) {
  $version = [int]$obj.versionNumber + 1
  Set-ADObject -Identity $gpo.Path -Server $pdc -Replace @{ gPCMachineExtensionNames = $ext; versionNumber = $version }
  $gpt = Join-Path $policy 'GPT.INI'
  $lines = @('[General]', 'Version=' + $version)
  if (Test-Path -LiteralPath $gpt) {
    $lines = [IO.File]::ReadAllLines($gpt, [Text.Encoding]::Default) | ForEach-Object { if ($_ -match '^Version=') { 'Version=' + $version } else { $_ } }
  }
  [IO.File]::WriteAllLines($gpt, [string[]]$lines, [Text.Encoding]::Default)
  Write-Host ('version de la GPO : ' + $version)
}

# 4. liaison a l'unite d'organisation
$linked = (Get-GPInheritance -Target $Ou -Server $pdc).GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }
if (-not $linked) {
  if ($PSCmdlet.ShouldProcess($Ou, 'lier la GPO')) { $null = New-GPLink -Name $GpoName -Target $Ou -LinkEnabled Yes -Server $pdc; Write-Host ('GPO liee a ' + $Ou) }
}
Write-Host 'Termine. Sur un poste pilote de cette unite : gpupdate /force, puis redemarrer ; controler ensuite %ProgramFiles%\DDI-Buntu\enroll.log.'
`

/** Empreinte SHA-1 en hexadécimal, comme Windows l'affiche. */
const thumbprint = (c: X509Certificate) => c.fingerprint.replace(/:/g, '')

/** Autorités racines (auto-signées) contenues dans des PEM : seules celles-là entrent dans les racines de confiance des postes. */
export function trustAnchors(...pems: string[]): GpoFiles {
  const out: GpoFiles = {}
  for (const pem of pems) {
    for (const block of pem.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----/g) ?? []) {
      try {
        const c = new X509Certificate(block)
        if (c.subject === c.issuer && c.verify(c.publicKey)) out[`anchor-${thumbprint(c)}.cer`] = Buffer.from(c.raw)
      } catch { /* bloc illisible : ignoré */ }
    }
  }
  return out
}

/** Tous les fichiers du dossier de démarrage de la GPO : enroll.ps1 (avec marque d'ordre d'octets), le script de démarrage et les autorités à approuver. */
export function gpoFiles(enrollPs1: string, anchors: GpoFiles): GpoFiles {
  const all: GpoFiles = { 'enroll.ps1': Buffer.concat([BOM, Buffer.from(enrollPs1, 'utf8')]), 'ddi-demarrage.ps1': Buffer.from(STARTUP.replace(/\r?\n/g, '\r\n'), 'ascii'), ...anchors }
  for (const name of Object.keys(all)) if (!NAME_RE.test(name)) throw new Error('enroll_gpo_name')
  return all
}

/** Le script de déploiement, avec le script d'enrôlement et les autorités à confiance embarqués. */
export function gpoScript(enrollPs1: string, anchors: GpoFiles): string {
  const lines = Object.entries(gpoFiles(enrollPs1, anchors)).map(([name, data]) => `  '${name}' = '${data.toString('base64')}'`)
  return TEMPLATE.replace('__FILES__', () => lines.join('\r\n')).replace(/\r?\n/g, '\r\n')
}

export const GPO_NAME = 'DDI-Buntu enrolement'
/** Extension « scripts » de la stratégie de groupe : à déclarer sur la GPO pour que les postes lisent scripts.ini. */
export const CSE_SCRIPTS = '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}'
export const TOOL_SCRIPTS = '{40B6664F-4972-11D1-A7CA-0000F87571E3}'

/** Ajoute l'extension « scripts » à gPCMachineExtensionNames (liste de groupes « [{extension}{outil}…] » triée) sans toucher aux autres. */
export function mergeExtensions(current: string): { value: string; changed: boolean } {
  const groups = current.match(/\[[^\]]*\]/g) ?? []
  let found = false, changed = false
  const out = groups.map((g) => {
    if (!g.startsWith('[' + CSE_SCRIPTS)) return g
    found = true
    if (g.includes(TOOL_SCRIPTS)) return g
    changed = true; return g.slice(0, -1) + TOOL_SCRIPTS + ']'
  })
  if (!found) { out.push('[' + CSE_SCRIPTS + TOOL_SCRIPTS + ']'); changed = true }
  out.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
  return { value: out.join(''), changed }
}

/** scripts.ini de la GPO (UTF-16 avec marque d'ordre d'octets, comme l'éditeur de GPO l'écrit) : lance le script de démarrage depuis SYSVOL. */
export function scriptsIni(dns: string, guid: string): Buffer {
  const text = `[Startup]\r\n0CmdLine=powershell.exe\r\n0Parameters=-NoProfile -ExecutionPolicy Bypass -File "\\\\${dns}\\SYSVOL\\${dns}\\Policies\\${guid}\\Machine\\Scripts\\Startup\\ddi-demarrage.ps1"\r\n`
  return Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')])
}
