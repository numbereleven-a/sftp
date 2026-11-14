param(
    [Parameter(Mandatory = $true)][string]$VisualStudioPath,
    [ValidateSet('x64', 'x86')][string[]]$Architecture = @('x64', 'x86')
)
$ErrorActionPreference = 'Stop'
$cmake = Join-Path $VisualStudioPath 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'
foreach ($arch in $Architecture) {
    $vcvars = Join-Path $VisualStudioPath 'VC/Auxiliary/Build/vcvars64.bat'
    if ($arch -eq 'x86') { $vcvars = Join-Path $VisualStudioPath 'VC/Auxiliary/Build/vcvars32.bat' }
    $output = Join-Path $PSScriptRoot "thirdparty/libssh2/build-$arch"
    $source = Join-Path $PSScriptRoot 'thirdparty/libssh2'
    $include = Join-Path $PSScriptRoot 'thirdparty/mbedtls/include'
    $crypto = Join-Path $PSScriptRoot "src/lib/mbedcrypto_$arch.lib"
    # Configure inside the selected compiler environment. Release libraries
    # contain no debug information or absolute source paths from __FILE__.
    $configure = 'call "{0}" >nul && "{1}" -S "{2}" -B "{3}" -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded -DCMAKE_C_FLAGS="/Brepro /experimental:deterministic /pathmap:{4}=." -DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DCRYPTO_BACKEND=mbedTLS -DMBEDTLS_INCLUDE_DIR="{5}" -DMBEDCRYPTO_LIBRARY="{6}"' -f $vcvars,$cmake,$source,$output,$PSScriptRoot,$include,$crypto
    $messages = & $env:COMSPEC /d /s /c "$configure 2>&1"
    if ($LASTEXITCODE -ne 0) { $messages | Write-Host }
    if ($LASTEXITCODE -ne 0) { throw "libssh2 configure failed: $arch" }
    $build = 'call "{0}" >nul && "{1}" --build "{2}" --target libssh2_static' -f $vcvars,$cmake,$output
    $messages = & $env:COMSPEC /d /s /c "$build 2>&1"
    if ($LASTEXITCODE -ne 0) { $messages | Write-Host }
    if ($LASTEXITCODE -ne 0) { throw "libssh2 build failed: $arch" }
    Copy-Item -LiteralPath (Join-Path $output 'src/libssh2.lib') -Destination (Join-Path $PSScriptRoot "src/lib/libssh2_$arch.lib")
    Write-Host "Rebuilt libssh2 ($arch, mbedTLS)."
}
