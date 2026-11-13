// Scripts PowerShell à exécuter SUR le serveur Windows (lecture seule) pour préparer la migration. Aucune modification de configuration.
export const PS_INVENTORY = `# Inventaire DNS / DHCP (lecture seule) — à exécuter sur le serveur Windows, en administrateur
$out = "$env:TEMP\\migration"; New-Item -ItemType Directory -Force $out | Out-Null
Get-DnsServerZone | Select-Object ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, DynamicUpdate, IsSigned, MasterServers |
  Export-Csv "$out\\dns-zones.csv" -NoTypeInformation -Encoding UTF8
Get-DnsServerForwarder | Out-File "$out\\dns-forwarders.txt"
Get-DhcpServerv4Scope | Select-Object ScopeId, Name, SubnetMask, StartRange, EndRange, LeaseDuration, State, SuperscopeName |
  Export-Csv "$out\\dhcp-scopes.csv" -NoTypeInformation -Encoding UTF8
Get-DhcpServerv4Failover -ErrorAction SilentlyContinue | Out-File "$out\\dhcp-failover.txt"
Get-DhcpServerv4Policy -ErrorAction SilentlyContinue | Out-File "$out\\dhcp-policies.txt"
Get-DhcpServerv4Class -ErrorAction SilentlyContinue | Out-File "$out\\dhcp-classes.txt"
Get-DhcpServerv4Filter -ErrorAction SilentlyContinue | Out-File "$out\\dhcp-mac-filters.txt"
Write-Host "Inventaire écrit dans $out"`
export const PS_DHCP = `# Export de la configuration DHCP (étendues, plages, exclusions, réservations, options) — fichier à importer dans l'onglet « DHCP »
Export-DhcpServer -ComputerName $env:COMPUTERNAME -File "$env:TEMP\\dhcp-export.xml" -Force
# Avec les baux actifs (fichier plus gros ; les baux ne sont pas encore repris à l'import) : ajouter -Leases
Write-Host "Écrit : $env:TEMP\\dhcp-export.xml"`
export const PS_DNS = `# Export des zones primaires (hors zones automatiques) au format fichier de zone — à importer dans l'onglet « DNS », zone par zone
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
