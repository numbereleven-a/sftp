param(
    [Parameter(Mandatory = $true)]
    [string]$VcVarsPath,
    [ValidateSet('x64', 'x86')]
    [string]$Architecture = 'x64',
    [string]$PhpPath,
    [string]$PythonPath = 'python.exe'
)
$ErrorActionPreference = 'Stop'
$repoDir = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $PSScriptRoot "build\${Architecture}"
$null = New-Item -ItemType Directory -Force -Path $outputDir
$toolchain = (Resolve-Path -LiteralPath $VcVarsPath).Path
$failed = 0
$passed = 0
function Invoke-Test {
    param([string]$Name, [string[]]$Arguments = @())
    & (Join-Path $outputDir "${Name}.exe") @Arguments
    if ($LASTEXITCODE -eq 0) { $script:passed++ } else { $script:failed++ }
}
Push-Location $repoDir
try {
    $testNames = @('download_skip_test', 'lan_transfer_test', 'crlf_test', 'sftpcrlf_test', 'trailcr_test', 'lan3_test', 'php_signer_test', 'plugin_load_test')
    foreach ($test in $testNames) {
        $obj = $outputDir + '\\'
        $exe = Join-Path $outputDir "${test}.exe"
        $sources = '"tests\{0}.cpp"' -f $test
        if ($test -in @('crlf_test','sftpcrlf_test','trailcr_test')) { $sources += ' src\core\TextConversion.cpp' }
        if ($test -eq 'lan3_test') { $sources += ' src\core\LanPair.cpp src\core\LanPairSession.cpp src\core\ProfileSettings.cpp src\core\TrustedInstallerToken.cpp src\core\DllExceptionBarrier.cpp' }
        $command = 'call "{0}" >nul && cl /nologo /std:c++20 /EHsc /O2 /Gy /MT /FI global.h /DSFTP_ALLINONE /DLIBSSH2_API= /I src /I src\include {1} /Fo:"{2}" /Fe:"{3}" /link /OPT:REF ws2_32.lib bcrypt.lib crypt32.lib iphlpapi.lib advapi32.lib user32.lib shell32.lib ole32.lib' -f $toolchain, $sources, $obj, $exe
        & $env:COMSPEC /d /s /c $command
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed: ${test}" }
    }
    foreach ($test in @('download_skip_test','crlf_test','sftpcrlf_test','trailcr_test','lan3_test')) { Invoke-Test $test }
    foreach ($case in @('resume', 'fresh', 'empty', 'complete', 'upload-empty', 'upload-spaces', 'upload-closed', 'upload-ok', 'invalid-negative', 'invalid-text')) {
        Invoke-Test 'lan_transfer_test' @($case)
    }
    if ($PhpPath) {
        $signer = Join-Path $outputDir 'php_signer_test.exe'
        foreach ($mode in @('plain','hash')) {
            $testArgs = @('tests/php_agent_test.py', $PhpPath, $signer)
            if ($mode -eq 'hash') { $testArgs += '--hash-only' }
            & $PythonPath @testArgs
            if ($LASTEXITCODE -eq 0) { $passed++ } else { $failed++ }
        }
    }
} finally {
    Pop-Location
}
Write-Host "${Architecture}: ${passed} groups passed, ${failed} failed."
if ($failed -ne 0) { exit 1 }
