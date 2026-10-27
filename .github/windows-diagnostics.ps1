$ErrorActionPreference = 'Stop'
$base = Join-Path $env:RUNNER_TEMP 'omgs-windows-diagnostic'
$workspace = Join-Path $base 'workspace'
$scratch = Join-Path $base 'scratch'
New-Item -ItemType Directory -Force "$workspace/tests/security", $scratch | Out-Null
Set-Content "$workspace/check.txt" 'vulnerable'
Set-Content "$base/outside.txt" 'outside-private'
$body = "@echo SCRIPT_RAN`r`n@exit /b 1`r`n"
Set-Content "$workspace/root.cmd" $body
Set-Content "$workspace/tests/security/nested.cmd" $body
$probe = @'
@echo off
echo CWD
cd
echo ROOT_READ
type check.txt
echo NESTED_DIR
dir tests\security
echo NESTED_READ
type tests\security\nested.cmd
echo ROOT_EXEC
cmd.exe /d /c root.cmd
echo ROOT_EXIT=%errorlevel%
echo NESTED_EXEC
cmd.exe /d /c tests\security\nested.cmd
echo NESTED_EXIT=%errorlevel%
echo NESTED_ABSOLUTE_EXEC
cmd.exe /d /c "%cd%\tests\security\nested.cmd"
echo ABSOLUTE_EXIT=%errorlevel%
echo OUTSIDE_READ
type ..\outside.txt
exit /b 0
'@
Set-Content "$workspace/probe.cmd" $probe
foreach ($case in 'root', 'subdirs', 'file') {
    $grants = @($workspace, $scratch)
    if ($case -eq 'subdirs') { $grants += @("$workspace/tests", "$workspace/tests/security") }
    if ($case -eq 'file') { $grants += "$workspace/tests/security/nested.cmd" }
    $config = @{
        version = '1.0.0'; containment = 'processcontainer'
        process = @{
            commandLine = 'cmd.exe /d /c probe.cmd'; cwd = $workspace; timeout = 10000
            env = @("SYSTEMROOT=$env:SYSTEMROOT", "PATH=$env:SYSTEMROOT\System32;$env:SYSTEMROOT", "TEMP=$scratch", "TMP=$scratch", "USERPROFILE=$scratch", "LOCALAPPDATA=$scratch")
        }
        filesystem = @{ readwritePaths = $grants; readonlyPaths = @(); deniedPaths = @() }
        network = @{ egress = @{ default = 'deny' }; ingress = @{ default = 'deny'; hostLoopback = 'deny' } }
        ui = @{ disable = $false; injection = $false; clipboard = 'none' }
        processContainer = @{ ui = @{ isolation = 'desktop' } }
    }
    $path = Join-Path $base "$case.json"
    $config | ConvertTo-Json -Depth 8 | Set-Content $path
    Write-Output "CASE=$case GRANTS=$($grants -join ',')"
    & $env:OMGS_MXC_EXEC --config $path
    Write-Output "EXECUTOR_EXIT=$LASTEXITCODE"
}
exit 0
