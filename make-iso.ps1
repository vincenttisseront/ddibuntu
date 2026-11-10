<#
.SYNOPSIS
  Construit l'ISO DDI-Buntu depuis le depot, en un seul script (Windows 10/11 + Docker Desktop).
.DESCRIPTION
  1. construit la console web (Node 22 dans Docker) -> webui\.output
  2. construit l'ISO (Ubuntu 24.04 dans Docker)     -> <OutDir>\ddibuntu-<version>-amd64.iso
  Premier lancement : telecharge ~4 Go, prevoir 25 Go de disque et 4 Go de memoire pour Docker.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\make-iso.ps1
  .\make-iso.ps1 -OutDir D:\iso -Timeout 5 -CaCert C:\certs\proxy.pem
#>
param(
    [string]$OutDir = (Join-Path $PSScriptRoot 'dist'),
    [int]$Timeout = 10,
    [string]$CaCert = '',
    [switch]$SkipConsole
)
$ErrorActionPreference = 'Stop'
function Fail($m) { Write-Host "ERREUR : $m" -ForegroundColor Red; exit 1 }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Fail "Docker n'est pas installe. Installez Docker Desktop puis relancez." }
& docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker Desktop ne repond pas. Demarrez-le, attendez qu'il soit pret, puis relancez." }

$Root = $PSScriptRoot
if (-not (Test-Path -LiteralPath (Join-Path $Root 'src\rootfs'))) { Fail "lancez ce script depuis la racine du depot (src\ introuvable)" }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$Out = (Resolve-Path -LiteralPath $OutDir).Path

# --- 1. Console web : construite dans le conteneur (copie hors du volume Windows : liens symboliques et vitesse)
if (-not $SkipConsole) {
    Write-Host "==> [1/2] Construction de la console web (node:22-bookworm)"
    $cmd = 'set -e; mkdir /w; cd /src; tar --exclude=node_modules --exclude=.output --exclude=.nuxt -cf - . | tar -xf - -C /w; ' +
           'cd /w; npm ci --no-audit --no-fund; npx nuxt build; rm -rf /src/.output; cp -r /w/.output /src/.output; test -f /src/.output/server/index.mjs'
    & docker run --rm -v "$((Join-Path $Root 'webui')):/src" node:22-bookworm sh -c $cmd
    if ($LASTEXITCODE -ne 0) { Fail "la construction de la console a echoue (code $LASTEXITCODE)" }
}
if (-not (Test-Path -LiteralPath (Join-Path $Root 'webui\.output\server\index.mjs'))) { Fail "webui\.output absent : relancez sans -SkipConsole" }

# --- 2. ISO
Write-Host "==> [2/2] Construction de l'ISO (ubuntu:24.04, plateforme linux/amd64)"
$extra = @()
if ($CaCert) {
    if (-not (Test-Path -LiteralPath $CaCert)) { Fail "certificat introuvable : $CaCert" }
    Copy-Item -LiteralPath $CaCert -Destination (Join-Path $Out '.ddibuntu-ca.pem') -Force
    $extra = @('--ca-cert', '/ddi-out/.ddibuntu-ca.pem')
}
& docker run --rm --platform linux/amd64 -v "${Root}:/ddi-src:ro" -v "${Out}:/ddi-out" ubuntu:24.04 `
    bash /ddi-src/build-ddibuntu.sh --in-container --out /ddi-out --timeout $Timeout @extra
if ($LASTEXITCODE -ne 0) { Fail "la construction de l'ISO a echoue (code $LASTEXITCODE)" }
Write-Host "==> Termine. ISO dans : $Out" -ForegroundColor Green
