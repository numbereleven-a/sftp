param(
    [Parameter(Mandatory = $true)]
    [string]$VcVarsPath,
    [ValidateSet('x64', 'x86')]
    [string]$Architecture = 'x64'
)
$ErrorActionPreference = 'Stop'
$repoDir = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $PSScriptRoot "build\${Architecture}"
$null = New-Item -ItemType Directory -Force -Path $outputDir
$toolchain = (Resolve-Path -LiteralPath $VcVarsPath).Path
$failed = 0
$passed = 0
Push-Location $repoDir
try {
    foreach ($test in @('download_skip_test', 'lan_transfer_test')) {
        $obj = Join-Path $outputDir "${test}.obj"
        $exe = Join-Path $outputDir "${test}.exe"
        $command = 'call "{0}" >nul && cl /nologo /std:c++20 /EHsc /O2 /Gy /MT /DSFTP_ALLINONE /DLIBSSH2_API= /I src /I src\include "tests\{1}.cpp" /Fo:"{2}" /Fe:"{3}" /link /OPT:REF user32.lib' -f $toolchain, $test, $obj, $exe
        & $env:COMSPEC /d /s /c $command
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed: ${test}" }
    }
    & (Join-Path $outputDir 'download_skip_test.exe')
    if ($LASTEXITCODE -eq 0) { $passed++ } else { $failed++ }
    foreach ($case in @('resume', 'fresh', 'empty', 'complete', 'upload-empty', 'upload-spaces', 'upload-closed', 'upload-ok')) {
        & (Join-Path $outputDir 'lan_transfer_test.exe') $case
        if ($LASTEXITCODE -eq 0) { $passed++ } else { $failed++ }
    }
} finally {
    Pop-Location
}
Write-Host "${Architecture}: ${passed} groups passed, ${failed} failed."
if ($failed -ne 0) { exit 1 }
