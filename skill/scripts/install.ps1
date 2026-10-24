# OMGS first-run binary bootstrap (Windows PowerShell).
# Downloads the platform binary from a release base, verifies SHA-256,
# installs without elevation, and prints the installed path.
$ErrorActionPreference = 'Stop'
$Base = if ($env:OMGS_RELEASE_BASE) { $env:OMGS_RELEASE_BASE } else { 'https://github.com/OpenAdminOS/oh-my-god-security/releases/latest/download' }
$DestRoot = if ($env:OMGS_HOME) { $env:OMGS_HOME } else { Join-Path $env:USERPROFILE '.local\share\omgs' }
$Dest = Join-Path $DestRoot 'bin'
$asset = 'omgs-x86_64-pc-windows-msvc.exe'

$tmp = Join-Path $env:TEMP ('omgs-bootstrap-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    Write-Output "downloading $Base/$asset"
    Invoke-WebRequest "$Base/$asset" -OutFile (Join-Path $tmp $asset)
    Invoke-WebRequest "$Base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')
    $expected = $null
    foreach ($line in Get-Content (Join-Path $tmp 'SHA256SUMS')) {
        $parts = $line -split '\s+'
        if ($parts.Count -ge 2 -and ($parts[1] -eq $asset -or $parts[1] -eq ('*' + $asset))) { $expected = $parts[0] }
    }
    if (-not $expected) { throw "no checksum entry for $asset" }
    $actual = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) { throw "checksum mismatch for $asset" }
    New-Item -ItemType Directory -Force $Dest | Out-Null
    Copy-Item (Join-Path $tmp $asset) (Join-Path $Dest 'omgs.exe') -Force
    $installed = Join-Path $Dest 'omgs.exe'
    Write-Output $installed
    & $installed --version
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
