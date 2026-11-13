// Scripts PowerShell à exécuter SUR le serveur Windows (lecture seule) pour préparer la migration. Aucune modification de configuration.
export const PS_INVENTORY = `# Inventaire DNS / DHCP (lecture seule) — à exécuter en administrateur sur le serveur Windows (ou un poste avec les outils RSAT DNS et DHCP)
$out = "$env:TEMP\\migration"; New-Item -ItemType Directory -Force $out | Out-Null
$dnsServer = $env:COMPUTERNAME   # ou le nom d'un autre serveur DNS, si ce poste n'héberge pas le rôle
if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
  Get-DnsServerZone -ComputerName $dnsServer | Select-Object ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, DynamicUpdate, IsSigned, MasterServers |
    Export-Csv "$out\\dns-zones.csv" -NoTypeInformation -Encoding UTF8
  Get-DnsServerForwarder -ComputerName $dnsServer | Out-File "$out\\dns-forwarders.txt"
} else {
  Write-Warning "Module DnsServer absent : DNS ignoré. Lancez ce script sur le serveur DNS, ou installez les outils RSAT DNS (Paramètres › Fonctionnalités facultatives, « Outils du serveur DNS »)."
}
if (Get-Command Get-DhcpServerv4Scope -ErrorAction SilentlyContinue) {
  Get-DhcpServerv4Scope | Select-Object ScopeId, Name, SubnetMask, StartRange, EndRange, LeaseDuration, State, SuperscopeName |
    Export-Csv "$out\\dhcp-scopes.csv" -NoTypeInformation -Encoding UTF8
  Get-DhcpServerv4Failover -ErrorAction SilentlyContinue | Out-File "$out\\dhcp-failover.txt"
  Get-DhcpServerv4Policy -ErrorAction SilentlyContinue | Out-File "$out\\dhcp-policies.txt"
  Get-DhcpServerv4Class -ErrorAction SilentlyContinue | Out-File "$out\\dhcp-classes.txt"
  Get-DhcpServerv4Filter -ErrorAction SilentlyContinue | Out-File "$out\\dhcp-mac-filters.txt"
} else {
  Write-Warning "Module DhcpServer absent : DHCP ignoré."
}
Write-Host "Inventaire écrit dans $out"`
export const PS_DHCP = `# Export de la configuration DHCP (étendues, plages, exclusions, réservations, options) — fichier à importer dans l'onglet « DHCP »
Export-DhcpServer -ComputerName $env:COMPUTERNAME -File "$env:TEMP\\dhcp-export.xml" -Force
# Avec les baux actifs (fichier plus gros ; les baux ne sont pas encore repris à l'import) : ajouter -Leases
Write-Host "Écrit : $env:TEMP\\dhcp-export.xml"`
export const PS_DNS = `# Export des zones primaires (hors zones automatiques) au format fichier de zone — à importer dans l'onglet « DNS », zone par zone
if (-not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) { Write-Warning "Module DnsServer absent : exécutez ce script sur le serveur DNS (rôle installé)."; return }
$dest = "$env:TEMP\\dns-export"; New-Item -ItemType Directory -Force $dest | Out-Null
Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' } | ForEach-Object {
  $f = "export-$($_.ZoneName).dns"
  dnscmd /ZoneExport $_.ZoneName $f | Out-Null
  Copy-Item "$env:SystemRoot\\System32\\dns\\$f" "$dest\\$f" -Force
}
Write-Host "Fichiers de zone dans $dest"`

export const PS_LEASES = `# Export des baux DHCP actifs (adresse, MAC, nom, expiration en UTC) — fichier à déposer dans l'étape « DHCP » pour que les clients gardent leur adresse
Get-DhcpServerv4Scope | ForEach-Object { Get-DhcpServerv4Lease -ScopeId $_.ScopeId } |
  Select-Object IPAddress, ClientId, HostName, AddressState, @{ n = 'ExpiryUtc'; e = { $_.LeaseExpiryTime.ToUniversalTime().ToString('s') } } |
  Export-Csv "$env:TEMP\\dhcp-leases.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Écrit : $env:TEMP\\dhcp-leases.csv"`

export const PS_PUSH = `# Envoi planifié des baux vers la console, TANT QUE Windows sert encore les clients (coexistence). À lancer toutes les 5 minutes, par exemple :
#   Register-ScheduledTask -TaskName DdiLeasePush -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)) -Action (New-ScheduledTaskAction -Execute powershell.exe -Argument '-File C:\\Scripts\\ddi-lease-push.ps1')
# Remplacez l'adresse de la console et le jeton d'API (rôle opérateur, créé dans Profil › Jetons d'API) ; ne laissez pas ce fichier lisible par tous.
$console = 'https://CONSOLE-DDI'
$token = 'COLLER-LE-JETON-ICI'
$csv = (Get-DhcpServerv4Scope | ForEach-Object { Get-DhcpServerv4Lease -ScopeId $_.ScopeId } |
  Select-Object IPAddress, ClientId, HostName, AddressState, @{ n = 'ExpiryUtc'; e = { $_.LeaseExpiryTime.ToUniversalTime().ToString('s') } } |
  ConvertTo-Csv -NoTypeInformation) -join "\`n"
Invoke-RestMethod -Method Post -Uri "$console/api/migration/leases/commit" -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body (@{ content = $csv; refresh = $true } | ConvertTo-Json)`

// Scripts de bascule : CONTRAIREMENT aux précédents, ils MODIFIENT le serveur Windows. Ils ne sont affichés que dans le plan de bascule.
export const PS_CUTOVER_TTL = `# J-1 : abaisser le TTL des enregistrements A / AAAA / CNAME à 300 s pour que la bascule se propage vite (exécuter sur le serveur DNS Windows)
if (-not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) { Write-Warning "Module DnsServer absent : exécutez ce script sur le serveur DNS."; return }
$ttl = [timespan]::FromSeconds(300)
Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and -not $_.IsReverseLookupZone -and $_.ZoneName -ne 'TrustAnchors' } | ForEach-Object {
  $z = $_.ZoneName
  Get-DnsServerResourceRecord -ZoneName $z | Where-Object { $_.RecordType -in 'A','AAAA','CNAME' -and $_.TimeToLive -gt $ttl } | ForEach-Object {
    $new = [ciminstance]::new($_); $new.TimeToLive = $ttl
    Set-DnsServerResourceRecord -ZoneName $z -OldInputObject $_ -NewInputObject $new
  }
}`
export const PS_CUTOVER_STOP = `# Bascule : désactiver les étendues DHCP Windows (les clients renouvellent alors auprès de la console). Garder la liste pour le retour arrière.
$ids = Get-DhcpServerv4Scope | Where-Object State -eq 'Active' | Select-Object -ExpandProperty ScopeId
$ids | ForEach-Object { $_.IPAddressToString } | Out-File "$env:TEMP\\scopes-actives.txt"
$ids | ForEach-Object { Set-DhcpServerv4Scope -ScopeId $_ -State InActive }
Write-Host "Étendues désactivées : $($ids.Count) (liste dans $env:TEMP\\scopes-actives.txt)"`
export const PS_CUTOVER_ROLLBACK = `# Retour arrière : réactiver les étendues désactivées par le script de bascule
Get-Content "$env:TEMP\\scopes-actives.txt" | ForEach-Object { Set-DhcpServerv4Scope -ScopeId $_ -State Active }
Write-Host "Étendues réactivées. Repointer ensuite les relais DHCP (ip helper-address) et les DNS des clients vers Windows."`

export const PS_RETIRE = `# Retrait des rôles Windows — À N'EXÉCUTER QU'APRÈS la bascule terminée et une période d'observation.
# 1. DHCP : désautoriser le serveur dans Active Directory puis arrêter le service (réversible : Add-DhcpServerInDC puis Start-Service).
Remove-DhcpServerInDC -DnsName $env:COMPUTERNAME
Stop-Service DHCPServer; Set-Service DHCPServer -StartupType Disabled
# 2. DNS : NE PAS retirer le rôle sur un contrôleur de domaine tant que ses zones sont intégrées à AD ou que d'autres DC l'utilisent.
#    Sur un serveur qui n'est pas contrôleur de domaine, une fois les clients repointés :
# Stop-Service DNS; Set-Service DNS -StartupType Disabled
# 3. Désinstallation définitive (irréversible sans réinstallation) — à décommenter seulement après sauvegarde :
# Uninstall-WindowsFeature DHCP -IncludeManagementTools`
