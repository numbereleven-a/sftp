param(
    [Parameter(Mandatory = $true)][string]$VcVarsPath,
    [ValidateSet('x64', 'x86')][string]$Architecture = 'x64',
    [string]$PythonPath = 'python.exe',
    [Parameter(Mandatory = $true)][string]$ShellPath,
    [string]$PhpPath
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$platform = if ($Architecture -eq 'x64') { 'x64' } else { 'Win32' }
$output = "tests/build/$Architecture"
Push-Location $repo
try {
    $null = New-Item -ItemType Directory -Force $output
    $compile = 'call "{0}" >nul && cl /nologo /O2 /MT /DHAVE_CONFIG_H /DLIBSSH2_MBEDTLS /DLIBSSH2_STATIC /I thirdparty/libssh2/include /I thirdparty/libssh2/src /I thirdparty/libssh2/build-{1}/src /I thirdparty/mbedtls/include tests/libssh2_boundary_test.c /Fo:{2}/libssh2_boundary_test.obj /Fe:{2}/libssh2_boundary_test.exe /link src/lib/libssh2_{1}.lib src/lib/mbedcrypto_{1}.lib ws2_32.lib bcrypt.lib 2>&1' -f $VcVarsPath,$Architecture,$output
    & $env:COMSPEC /d /s /c $compile
    if ($LASTEXITCODE) { throw 'Packet boundary test compilation failed' }
    foreach ($case in @('valid-name','malformed-name','status-ok','status-error','short-etm','ext-info')) {
        & "$output/libssh2_boundary_test.exe" $case
        if ($LASTEXITCODE) { throw "Packet boundary test failed: $case" }
    }
    $objects = Get-ChildItem "build/.intermediates/SFTPplug/${platform}_Release" -Filter '*.obj' |
        Where-Object Name -ne 'SessionImport.obj' |
        ForEach-Object { '"build/.intermediates/SFTPplug/{0}_Release/{1}"' -f $platform,$_.Name }
    if (!$objects) { throw 'Build the Release plugin before running SSH tests' }
    $objects | Set-Content "$output/ssh-objects.rsp" -Encoding ascii
    $compile = 'call "{0}" >nul && cl /c /nologo /std:c++20 /EHsc /O2 /MT /GR- /FI global.h /DSFTP_ALLINONE /DLIBSSH2_API= /I src /I src/include tests/ssh_transfer_test.cpp /Fo:{2}/ssh_transfer_test.obj && link /nologo /OUT:{2}/ssh_transfer_test.exe /SUBSYSTEM:CONSOLE /LTCG /OPT:REF {2}/ssh_transfer_test.obj @{2}/ssh-objects.rsp /LIBPATH:src/lib libssh2_{1}.lib mbedcrypto_{1}.lib argon2_a_{1}.lib ws2_32.lib bcrypt.lib crypt32.lib winhttp.lib iphlpapi.lib shlwapi.lib advapi32.lib user32.lib gdi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib comctl32.lib dbghelp.lib 2>&1' -f $VcVarsPath,$Architecture,$output
    & $env:COMSPEC /d /s /c $compile
    if ($LASTEXITCODE) { throw 'SSH integration test compilation failed' }
    $arguments = @('tests/ssh_transfer_test.py', "$output/ssh_transfer_test.exe", '--shell', $ShellPath)
    if ($PhpPath) { $arguments += @('--php', $PhpPath) }
    & $PythonPath @arguments
    if ($LASTEXITCODE) { throw 'SSH integration tests failed' }
} finally {
    Pop-Location
}
