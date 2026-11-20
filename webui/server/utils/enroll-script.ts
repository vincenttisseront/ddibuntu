// Script PowerShell d'enrôlement (0.18.0), généré par la console et déployé par GPO. Il tourne en compte machine (SYSTEM) : la clé naît dans le
// magasin de l'ordinateur (non exportable), la demande s'authentifie en Kerberos avec le compte de l'ordinateur, le certificat est lié à la clé.
// Seules deux valeurs sont insérées (nom de la console, nom de l'autorité) ; elles sont validées avant et échappées pour une chaîne PowerShell.
import { DNS_RE } from './pki-certs'

// PowerShell traite aussi les apostrophes typographiques (‘ ’ ‚ ‛) comme des guillemets simples : toutes sont doublées
const psq = (v: string) => v.replace(/['\u2018\u2019\u201A\u201B]/g, (q) => q + q)

const TEMPLATE = String.raw`<#
 DDI-Buntu : certificat de poste (EAP-TLS) émis par la PKI du DDI.
 Généré par la console du DDI. À exécuter en SYSTEM :
   - tâche planifiée : lancer une fois "powershell.exe -ExecutionPolicy Bypass -File enroll.ps1 -Install" (par exemple en script de démarrage d'une GPO) ;
   - essai à la main (invite PowerShell lancée en SYSTEM) : "enroll.ps1 -Now".
 La clé privée est créée sur ce poste (non exportable) et n'en sort jamais. Journal : %ProgramFiles%\DDI-Buntu\enroll.log
#>
param([switch]$Install, [switch]$Now, [switch]$Force)
$ErrorActionPreference = 'Stop'
$Console   = '__HOST__'
$IssuerCn  = '__ISSUER__'
$RenewDays = 30
$Dir = Join-Path $env:ProgramFiles 'DDI-Buntu'   # Program Files : seuls les administrateurs y créent un dossier (ProgramData laisserait un utilisateur préparer le dossier d'une tâche SYSTEM)
$Log = Join-Path $Dir 'enroll.log'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

function Write-Log([string]$m) {
  $line = '{0:s} {1}' -f (Get-Date), $m
  Add-Content -Path $Log -Value $line
  if ((Get-Item $Log).Length -gt 500KB) { Move-Item -Force $Log ($Log + '.old') }
  Write-Output $line
}

if ($Install) {
  $dest = Join-Path $Dir 'enroll.ps1'
  Copy-Item -Force $PSCommandPath $dest
  $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $dest)
  $trigger = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Daily -At '03:30'))
  $princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName 'DDI-Buntu enrolement' -Action $action -Trigger $trigger -Principal $princ -Force | Out-Null
  Write-Log 'tache planifiee installee'
  return
}

$domain = (Get-CimInstance Win32_ComputerSystem).Domain
$fqdn = ('{0}.{1}' -f $env:COMPUTERNAME, $domain).ToLower()

# un certificat valable et émis par la PKI du DDI existe déjà : rien à faire
if (-not $Force) {
  $have = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
    $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays($RenewDays) -and $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true) -eq $IssuerCn -and ($_.DnsNameList.Unicode -contains $fqdn)
  }
  if ($have) { Write-Log ('certificat deja en place (expire le {0:d})' -f ($have | Sort-Object NotAfter -Descending | Select-Object -First 1).NotAfter); return }
}
if (-not $Now) { Start-Sleep -Seconds (Get-Random -Minimum 0 -Maximum 300) }   # étale la charge sur la console

$work = Join-Path $env:TEMP ('ddi-enroll-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
  $inf = Join-Path $work 'req.inf'; $req = Join-Path $work 'req.csr'
  @(
    '[Version]', 'Signature="$Windows NT$"', '[NewRequest]',
    ('Subject = "CN={0}"' -f $env:COMPUTERNAME),
    'KeySpec = 1', 'KeyLength = 2048', 'Exportable = FALSE', 'MachineKeySet = TRUE', 'UserProtected = FALSE', 'UseExistingKeySet = FALSE',
    'ProviderName = "Microsoft Software Key Storage Provider"', 'ProviderType = 0', 'RequestType = PKCS10', 'KeyUsage = 0xA0', 'HashAlgorithm = SHA256'
  ) | Set-Content -Path $inf -Encoding ASCII
  & certreq.exe -new -q $inf $req | Out-Null
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $req)) { throw 'creation de la demande impossible (certreq -new)' }
  $csr = (Get-Content -Raw $req).Trim()

  $url = 'https://{0}/api/enroll/v1/machine' -f $Console
  $body = (@{ csr = @{ pem = $csr } } | ConvertTo-Json -Compress)
  $reply = $null
  foreach ($wait in 0, 30, 60, 120, 240) {
    if ($wait) { Write-Log ('nouvel essai dans {0} s' -f $wait); Start-Sleep -Seconds $wait }
    try {
      $r = Invoke-WebRequest -Uri $url -Method Post -UseDefaultCredentials -UseBasicParsing -ContentType 'application/json' -Body $body -TimeoutSec 120
      $reply = $r.Content | ConvertFrom-Json
      break
    } catch {
      $code = 0; $detail = ''
      if ($_.Exception.Response) {
        $code = [int]$_.Exception.Response.StatusCode
        try { $detail = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() } catch { }
      }
      Write-Log ('refus ou erreur HTTP {0} {1} {2}' -f $code, $_.Exception.Message, $detail)
      # 401 / 403 / 404 : inutile d'insister ; 409, 429, 5xx ou pas de reponse : on reessaie
      if ($code -in 400, 401, 403, 404, 413, 422) { throw ('enrolement refuse (HTTP {0})' -f $code) }
    }
  }
  if (-not $reply) { throw 'la console n''a pas repondu' }

  $cer = Join-Path $work 'cert.cer'; $chain = Join-Path $work 'chain.pem'
  Set-Content -Path $cer -Value $reply.certificate -Encoding ASCII
  Set-Content -Path $chain -Value $reply.chain -Encoding ASCII
  & certreq.exe -accept -machine -q $cer | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'liaison du certificat a la cle impossible (certreq -accept)' }
  & certutil.exe -addstore -f CA $chain | Out-Null
  Write-Log ('certificat installe : serie {0}, expire le {1}' -f $reply.serial, $reply.notAfter)
} catch {
  Write-Log ('ECHEC : ' + $_.Exception.Message)
  exit 1
} finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
`

/** Le script prêt à déployer ; refuse un nom de console ou d'autorité inattendu (jamais interpolé sans contrôle). */
export function enrollScript(host: string, issuerCn: string): string {
  if (!DNS_RE.test(host)) throw new Error('enroll_host')
  if (!issuerCn || issuerCn.length > 128 || /[\x00-\x1f\x7f]/.test(issuerCn)) throw new Error('enroll_issuer')
  return TEMPLATE.replace('__HOST__', () => psq(host)).replace('__ISSUER__', () => psq(issuerCn)).replace(/\r?\n/g, '\r\n')
}
