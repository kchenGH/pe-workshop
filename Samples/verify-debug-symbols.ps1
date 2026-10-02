[CmdletBinding()]
param([string]$Objdump = 'C:\msys64\ucrt64\bin\objdump.exe')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$expectedNames = @('global_counter', 'banner', 'seed', 'alias', 'local_total', 'scale', 'pair', 'values', 'pointer', 'local_mode', 'block_value')
foreach ($name in @('DebugSymbolsDemo.exe', 'build/DebugSymbolsDwarf5.exe', 'build/DebugSymbolsStripped.exe')) {
    $path = Join-Path $PSScriptRoot $name
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing debug fixture: $name" }
}
if (-not (Test-Path -LiteralPath $Objdump)) { throw 'GNU objdump is required for this independent fixture check.' }
foreach ($pair in @(@('DebugSymbolsDemo.exe', '4'), @('build/DebugSymbolsDwarf5.exe', '5'))) {
    $dump = & $Objdump --dwarf=info --wide (Join-Path $PSScriptRoot $pair[0]) 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "objdump failed for $($pair[0])" }
    if ($dump -notmatch ('Version:\s+' + $pair[1])) { throw "Wrong DWARF version for $($pair[0])" }
    foreach ($symbol in $expectedNames) {
        if ($dump -notmatch ('DW_AT_name\s*:[^\r\n]*\b' + [regex]::Escape($symbol) + '\b')) { throw "Missing independently decoded symbol: $symbol" }
    }
    $dump | Set-Content -LiteralPath (Join-Path $PSScriptRoot ('build/dwarf-' + $pair[1] + '-info.txt'))
    Write-Output "PASS objdump DWARF $($pair[1]): all eleven expected variable/parameter names."
}
$stripped = & $Objdump --dwarf=info (Join-Path $PSScriptRoot 'build/DebugSymbolsStripped.exe') 2>&1 | Out-String
if ($LASTEXITCODE -ne 0 -or $stripped.Contains('DW_TAG_variable')) { throw 'Stripped fixture unexpectedly contains DWARF variables.' }
$demo = Join-Path $PSScriptRoot 'DebugSymbolsDemo.exe'
$output = & $demo | Out-String
if ($LASTEXITCODE -ne 0 -or $output.TrimEnd() -ne 'PE Workshop DWARF demo: result 34.') { throw 'Debug demo output or exit code differed.' }
Write-Output 'PASS stripped fixture and harmless demo output/exit code.'
