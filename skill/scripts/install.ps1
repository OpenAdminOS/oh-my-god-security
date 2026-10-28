# Per-user bootstrap. No test verifier or signature bypass is accepted here.
$ErrorActionPreference = 'Stop'
if ($args.Count -ne 0) { throw 'No installer arguments are accepted' }
$env:RUSTUP_AUTO_INSTALL = '0'
$SkillDir = Split-Path $PSScriptRoot -Parent
$Version = (Get-Content -Raw (Join-Path $SkillDir 'VERSION')).Trim()
if ($Version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$') { throw 'Invalid skill/VERSION' }
$Base = if ($env:OMGS_RELEASE_BASE) { $env:OMGS_RELEASE_BASE.TrimEnd('/') } else { "https://github.com/OpenAdminOS/oh-my-god-security/releases/download/v$Version" }
$DestRoot = if ($env:OMGS_HOME) { $env:OMGS_HOME } else { Join-Path $env:USERPROFILE '.local\share\omgs' }
if (-not ($DestRoot -match '^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+)')) { throw 'OMGS_HOME must be absolute' }
# Owner sets this exact public certificate subject before the first public release.
$OmgsSubject = 'CN=OWNER_WINDOWS_SIGNER_SUBJECT'
$MicrosoftSubject = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
$asset = 'omgs-x86_64-pc-windows-msvc.exe'
$arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToUpperInvariant()
$platform = switch ($arch) { 'X64' { 'Windows/AMD64' } 'ARM64' { 'Windows/ARM64' } default { throw "Unsupported Windows architecture $arch" } }
$row = @(Get-Content (Join-Path $SkillDir 'mxc-pins.txt') | Where-Object { ($_ -split '\s+')[0] -ceq $platform })
if ($row.Count -ne 1) { throw 'Missing or duplicate MXC platform pin' }
$pin = $row[0] -split '\s+'
$mxcAsset = $pin[2]
$mxcFile = Split-Path $pin[1] -Leaf
Write-Output @'
OMGS installation consent
Download the version pinned in skill/VERSION from the OMGS GitHub release:
https://github.com/OpenAdminOS/oh-my-god-security/releases/download/v<VERSION>
If OMGS_RELEASE_BASE is set, use that explicitly configured bundle instead.
Download the OMGS binary (at most 100 MiB), the unmodified Microsoft MXC 1.0.1
executor for this platform (at most 100 MiB), SHA256SUMS and the MXC MIT notice
(at most 1 MiB each). Intel Macs have no MXC executor and cannot run proofs.
Verify OMGS with SHA256SUMS and, on macOS or Windows, the pinned publisher
signature. Verify MXC with SHA256SUMS, the executor hash pinned in this skill,
and Microsoft's signature where the OS supports it. Linux has no native
publisher signature check. With authenticated gh, also check OMGS provenance;
failed or unavailable provenance is reported as unverified, not as tampering.
Install without elevation under OMGS_HOME, defaulting to ~/.local/share/omgs
(%USERPROFILE%\.local\share\omgs on Windows): bin/omgs and mxc/1.0.1/.
No target dependencies or toolchains will be downloaded. Show the installed
paths, versions and verification results afterwards.
Download and install these files? Type yes to consent:
'@
Write-Output "Resolved: OMGS $Version; source $Base; destination $DestRoot; binary $asset; executor $mxcAsset"
if ((Read-Host) -cne 'yes') { throw 'Installation cancelled before downloads' }
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('omgs-bootstrap-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $tmp | Out-Null
function Fetch([string]$Name, [long]$Limit) {
    $to = Join-Path $tmp $Name
    if ($Base.StartsWith('https://', [StringComparison]::Ordinal)) {
        Add-Type -AssemblyName System.Net.Http
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient($handler)
        try {
            $uri = [uri]"$Base/$Name"
            for ($redirect = 0; $redirect -le 5; $redirect++) {
                if ($uri.Scheme -cne 'https') { throw 'Refusing non-HTTPS redirect' }
                $response = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                if ([int]$response.StatusCode -ge 300 -and [int]$response.StatusCode -lt 400) {
                    $uri = [uri]::new($uri, $response.Headers.Location)
                    $response.Dispose()
                    continue
                }
                $response.EnsureSuccessStatusCode() | Out-Null
                $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $output = [IO.File]::Create($to)
                try {
                    $buffer = New-Object byte[] 65536
                    $total = 0L
                    while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $total += $count
                        if ($total -gt $Limit) { throw "oversize download: $Name" }
                        $output.Write($buffer, 0, $count)
                    }
                } finally { $output.Dispose(); $stream.Dispose(); $response.Dispose() }
                break
            }
            if ($redirect -gt 5) { throw 'Too many redirects' }
        } finally { $client.Dispose(); $handler.Dispose() }
    } elseif (($Base -match '^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+)')) {
        Copy-Item -LiteralPath (Join-Path $Base $Name) -Destination $to
    } else { throw 'OMGS_RELEASE_BASE must be HTTPS or an absolute local bundle' }
    if ((Get-Item -LiteralPath $to).Length -gt $Limit) { throw "oversize download: $Name" }
}
function Checksum([string]$Name, [string]$Path = (Join-Path $tmp $Name)) {
    $entries = @(Get-Content (Join-Path $tmp 'SHA256SUMS') | ForEach-Object {
        $parts = $_ -split '\s+'
        if ($parts.Count -eq 2 -and ($parts[1] -ceq $Name -or $parts[1] -ceq "*$Name")) { $parts[0] }
    })
    if ($entries.Count -ne 1 -or $entries[0] -cnotmatch '^[0-9a-f]{64}$') { throw "missing or invalid checksum: $Name" }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entries[0]) { throw "checksum mismatch: $Name" }
    Write-Output "SHA256SUMS verified: $Name"
}
function Signature([string]$Path, [string]$Subject) {
    $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid' -or $null -eq $sig.SignerCertificate -or $sig.SignerCertificate.Subject -cne $Subject) { throw "publisher signature rejected: $Path" }
    Write-Output "Publisher signature verified: $Subject"
}
function Provenance([string]$Path) {
    # Windows PowerShell 5.1 promotes native stderr under Stop, even when redirected.
    # Keep this relaxation local to optional provenance, never integrity checks.
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    try {
        if (Get-Command gh -ErrorAction SilentlyContinue) {
            & gh auth status *> $null
            if ($LASTEXITCODE -eq 0) {
                & gh attestation verify $Path --repo OpenAdminOS/oh-my-god-security 2>&1 | Out-Host
                return ($LASTEXITCODE -eq 0)
            }
        }
    } catch { return $false }
    return $false
}

$StorageUser = [Security.Principal.WindowsIdentity]::GetCurrent().User
$TrustedStorageSids = @($StorageUser.Value, 'S-1-5-18', 'S-1-5-32-544')
function Check-Storage([string]$Path, [bool]$Ancestor = $false) {
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "owner-private installation storage '$Path': storage must be a directory without links; see README.md#storage-migration"
    }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne $StorageUser.Value -and -not ($Ancestor -and $owner -in $TrustedStorageSids)) {
        throw "owner-private installation storage '$Path': storage must be owned by the current user with a restrictive DACL; see README.md#storage-migration"
    }
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $raw.DiscretionaryAcl) { throw "owner-private installation storage '$Path': missing restrictive DACL" }
    foreach ($ace in $raw.DiscretionaryAcl) {
        # Like run storage, unknown ACEs fail closed and deny ACEs grant no access.
        if ($ace.AceType -eq [Security.AccessControl.AceType]::AccessDenied) { continue }
        if ($ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed) {
            throw "owner-private installation storage '$Path': unsupported storage DACL ACE"
        }
        if (($ace.AccessMask -band 0x500d0156) -ne 0 -and $ace.SecurityIdentifier.Value -notin $TrustedStorageSids) {
            throw "owner-private installation storage '$Path': storage is writable by another principal; see README.md#storage-migration"
        }
    }
}
function Check-Ancestors([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) { Check-Storage $current $true }
        if ($current.TrimEnd('\') -ieq $env:USERPROFILE.TrimEnd('\')) { break }
        $current = Split-Path $current -Parent
    }
}
function New-PrivateTree([string]$Path) {
    if (Test-Path -LiteralPath $Path) { Check-Storage $Path; return }
    $parent = Split-Path $Path -Parent
    if (-not (Test-Path -LiteralPath $parent)) { New-PrivateTree $parent }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($StorageUser)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($StorageUser, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    # Supply a protected owner-only DACL at creation, with no inherited grants.
    $directory = [IO.DirectoryInfo]::new($Path)
    $directory.Create($acl)
    Check-Storage $Path
}

$staged = [Collections.Generic.List[string]]::new()
function Stage([string]$Name, [string]$Destination) {
    $path = Join-Path (Split-Path $Destination -Parent) ('.omgs-' + [guid]::NewGuid().ToString('N') + [IO.Path]::GetExtension($Destination))
    # CreateNew reserves a unique sibling without overwriting an existing file.
    $output = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
    $staged.Add($path)
    try {
        $inputFile = [IO.File]::OpenRead((Join-Path $tmp $Name))
        try { $inputFile.CopyTo($output) } finally { $inputFile.Dispose() }
    } finally { $output.Dispose() }
    return $path
}
function Publish([string]$Path, [string]$Destination) {
    try {
        if ([IO.File]::Exists($Destination)) {
            [IO.File]::Replace($Path, $Destination, [NullString]::Value)
        } else {
            [IO.File]::Move($Path, $Destination)
        }
    } catch {
        Write-Output "Publication failed for '$Destination'."
        throw "Publication failed for '$Destination'. A running omgs.exe or MXC executor may hold the file. Stop it and retry. The existing destination is preserved on a sharing violation. Earlier published files remain individually verified and complete, but the installation may contain a mix of old and new files until retry succeeds. Staged temporary files are cleaned up. Cause: $($_.Exception.Message)"
    }
}

try {
    Fetch 'SHA256SUMS' 1048576
    Fetch $asset 104857600
    Checksum $asset
    Signature (Join-Path $tmp $asset) $OmgsSubject
    Fetch $mxcAsset 104857600
    Checksum $mxcAsset
    if ((Get-FileHash -LiteralPath (Join-Path $tmp $mxcAsset) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin[3]) { throw 'MXC pin mismatch' }
    Signature (Join-Path $tmp $mxcAsset) $MicrosoftSubject
    Fetch 'MXC-LICENSE.txt' 1048576
    Checksum 'MXC-LICENSE.txt'
    Write-Output "MXC 1.0.1 pin verified: $($pin[3])"
    $verified = Provenance (Join-Path $tmp $asset)
    if ($verified) { Write-Output 'OMGS provenance: verified' }
    else { Write-Output 'OMGS provenance: unverified (unavailable or failed; this alone is not evidence of tampering)' }
    $actual = & (Join-Path $tmp $asset) --version
    if ($LASTEXITCODE -ne 0 -or $actual -cne "omgs $Version") { throw "version mismatch: skill expects omgs $Version; binary reports $actual" }
    $bin = Join-Path $DestRoot 'bin'
    $mxc = Join-Path $DestRoot 'mxc/1.0.1'
    Check-Ancestors $bin
    Check-Ancestors $mxc
    New-PrivateTree $bin
    New-PrivateTree $mxc
    # Verify all destination siblings before the first atomic replacement.
    $stagedOmgs = Stage $asset (Join-Path $bin 'omgs.exe')
    $stagedMxc = Stage $mxcAsset (Join-Path $mxc $mxcFile)
    $stagedLicense = Stage 'MXC-LICENSE.txt' (Join-Path $mxc 'MXC-LICENSE.txt')
    Checksum $asset $stagedOmgs
    Signature $stagedOmgs $OmgsSubject
    Checksum $mxcAsset $stagedMxc
    Signature $stagedMxc $MicrosoftSubject
    Checksum 'MXC-LICENSE.txt' $stagedLicense
    Publish $stagedMxc (Join-Path $mxc $mxcFile)
    Publish $stagedLicense (Join-Path $mxc 'MXC-LICENSE.txt')
    Publish $stagedOmgs (Join-Path $bin 'omgs.exe')
    Write-Output "Installed MXC 1.0.1: $(Join-Path $mxc $mxcFile)"
    Write-Output "Installed $actual`: $(Join-Path $bin 'omgs.exe')"
} finally {
    foreach ($path in $staged) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
