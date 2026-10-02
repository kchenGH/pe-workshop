[CmdletBinding()]
param([string]$Gcc = 'C:\msys64\ucrt64\bin\gcc.exe')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not (Test-Path -LiteralPath $Gcc)) {
    $discoveredGcc = Get-Command gcc.exe -ErrorAction SilentlyContinue
    if ($discoveredGcc) { $Gcc = $discoveredGcc.Source }
    else { throw 'MinGW GCC is required to rebuild the DWARF sample. Pass -Gcc with its full path.' }
}
$toolDirectory = Split-Path -Parent $Gcc
$stripTool = Join-Path $toolDirectory 'strip.exe'
$objdumpTool = Join-Path $toolDirectory 'objdump.exe'
foreach ($tool in @($stripTool, $objdumpTool)) { if (-not (Test-Path -LiteralPath $tool)) { throw "Missing companion tool: $tool" } }
[void](New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot 'build'))
$previousSamplePath = $env:PATH
Push-Location $PSScriptRoot
try {
    $env:PATH = $toolDirectory + [IO.Path]::PathSeparator + $previousSamplePath
    $common = @('-O0', '-g3', '-std=c11', '-Wall', '-Wextra', '-Werror',
        '-nostdlib', '-fno-stack-protector', '-fno-builtin', "-fdebug-prefix-map=$PSScriptRoot=.",
        '-Wl,--no-insert-timestamp,-e,sample_main,--subsystem,console')
    & $Gcc @common -gdwarf-4 source/debug_symbols.c -lkernel32 -o DebugSymbolsDemo.exe
    if ($LASTEXITCODE -ne 0) { throw 'DWARF 4 sample compilation failed.' }
    & $Gcc @common -gdwarf-5 source/debug_symbols.c -lkernel32 -o build/DebugSymbolsDwarf5.exe
    if ($LASTEXITCODE -ne 0) { throw 'DWARF 5 sample compilation failed.' }
    Copy-Item -LiteralPath DebugSymbolsDemo.exe -Destination build/DebugSymbolsStripped.exe
    & $stripTool --strip-debug build/DebugSymbolsStripped.exe
    if ($LASTEXITCODE -ne 0) { throw 'Creating stripped fixture failed.' }
    & (Join-Path $PSScriptRoot 'verify-debug-symbols.ps1') -Objdump $objdumpTool
    if ($LASTEXITCODE -ne 0) { throw 'DWARF fixture verification failed.' }
}
finally { $env:PATH = $previousSamplePath; Pop-Location }
