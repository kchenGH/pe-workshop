[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$sampleNames = @('ConsoleDemo.exe', 'GuiDemo.exe', 'OriginalConsole.exe', 'ModifiedConsole.exe')
function Assert-Sample([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "Verification failed: $Message" }
}
foreach ($name in $sampleNames) {
    Assert-Sample (Test-Path -LiteralPath (Join-Path $PSScriptRoot $name)) "$name must exist"
}
. (Join-Path $PSScriptRoot 'source\pe-tools.ps1')
$manifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'manifest.json') | ConvertFrom-Json
$images = @{}
if (-not ('SampleImageHlp' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class SampleImageHlp {
    [DllImport("imagehlp.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern uint MapFileAndCheckSumW(string file, out uint stored, out uint computed);
}
'@
}
foreach ($name in $sampleNames) {
    $path = Join-Path $PSScriptRoot $name
    $bytes = [IO.File]::ReadAllBytes($path)
    $pe = Read-SamplePe $bytes
    $images[$name] = $pe
    Assert-Sample ($pe.Machine -eq 0x8664 -and $pe.Magic -eq 0x20b) "$name must be native x64 PE32+"
    Assert-Sample ($pe.ClrRva -eq 0) "$name must not require a CLR runtime"
    Assert-Sample ($pe.RelocationRva -gt 0) "$name must retain a base-relocation table"
    foreach ($section in $pe.Sections) {
        Assert-Sample (($section.RawPointer % $pe.FileAlignment) -eq 0) "$name/$($section.Name) raw alignment"
        Assert-Sample (($section.Rva % $pe.SectionAlignment) -eq 0) "$name/$($section.Name) RVA alignment"
        Assert-Sample (($section.RawPointer + $section.RawSize) -le $bytes.Length) "$name/$($section.Name) raw bounds"
        Assert-Sample (($section.Rva + $section.VirtualSize) -le $pe.SizeOfImage) "$name/$($section.Name) image bounds"
    }
    [uint32]$stored = 0; [uint32]$computed = 0
    Assert-Sample ([SampleImageHlp]::MapFileAndCheckSumW($path, [ref]$stored, [ref]$computed) -eq 0) "$name ImageHlp checksum call"
    Assert-Sample ($computed -eq (Get-SampleChecksum $bytes $pe.ChecksumOffset)) "$name checksum algorithm agrees with Windows ImageHlp"
    Assert-Sample (($stored -eq $computed) -eq ($name -ne 'ModifiedConsole.exe')) "$name expected checksum validity"
    $entry = @($manifest.files | Where-Object name -eq $name)
    Assert-Sample ($entry.Count -eq 1) "$name appears once in manifest"
    Assert-Sample ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash -eq $entry[0].sha256) "$name manifest SHA256"
    Write-Host "PASS $name structure, SHA256, imports, and checksum"
}
$original = $images['OriginalConsole.exe']; $modified = $images['ModifiedConsole.exe']
Assert-Sample ($images['GuiDemo.exe'].Subsystem -eq 2) 'GuiDemo uses Windows GUI subsystem'
Assert-Sample ($images['GuiDemo.exe'].Imports.functions -contains 'MessageBoxA') 'GuiDemo imports MessageBoxA'
foreach ($name in @('ConsoleDemo.exe', 'OriginalConsole.exe', 'ModifiedConsole.exe')) {
    Assert-Sample ($images[$name].Subsystem -eq 3) "$name uses console subsystem"
    Assert-Sample ($images[$name].Imports.functions -contains 'WriteFile') "$name imports WriteFile"
}
foreach ($name in @('ConsoleDemo.exe', 'GuiDemo.exe', 'OriginalConsole.exe')) {
    Assert-Sample (($images[$name].DllCharacteristics -band 0x160) -eq 0x160) "$name declares ASLR, NX, and high-entropy VA"
}
Assert-Sample (($modified.DllCharacteristics -band 0x160) -eq 0) 'ModifiedConsole removes the three declared mitigations'
Assert-Sample ($modified.SectionCount -eq $original.SectionCount + 1) 'ModifiedConsole adds exactly one section'
$demo = @($modified.Sections | Where-Object Name -eq '.demo')
Assert-Sample ($demo.Count -eq 1) 'ModifiedConsole contains .demo'
Assert-Sample ($demo[0].Characteristics -eq [uint32]3758096416) '.demo is read/write/execute code'
Assert-Sample ($modified.EntryRva -eq $demo[0].Rva) 'ModifiedConsole entry redirects to .demo'
Assert-Sample (($modified.Sections | Where-Object Name -eq '.text').Characteristics -eq [uint32]3758096416) 'ModifiedConsole .text is writable code'
Assert-Sample (($original.Imports | ConvertTo-Json -Depth 8 -Compress) -eq ($modified.Imports | ConvertTo-Json -Depth 8 -Compress)) 'patch preserves all original imports'
$modifiedBytes = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'ModifiedConsole.exe'))
Assert-Sample ($modifiedBytes[$demo[0].RawPointer] -eq 0xe9) '.demo starts with a relative JMP'
$displacement = [BitConverter]::ToInt32($modifiedBytes, $demo[0].RawPointer + 1)
Assert-Sample (($demo[0].Rva + 5 + $displacement) -eq $original.EntryRva) '.demo jumps directly to the original entry'
Assert-Sample ($modified.OverlayLength -gt 0 -and $original.OverlayLength -eq 0) 'only patched file has an overlay'
Assert-Sample ([Text.Encoding]::ASCII.GetString($modifiedBytes, $modified.OverlayOffset, $modified.OverlayLength) -eq "`r`nPE WORKSHOP TRAINING OVERLAY - harmless appended bytes; never executed.`r`n") 'overlay is explicitly labeled'
Assert-Sample ($modified.Checksum -eq $original.Checksum) 'original checksum is intentionally retained'
Assert-Sample ($modified.Timestamp -ne $original.Timestamp) 'timestamp changed'

# Every original byte is either retained or accounted for in the patch manifest.
$reconstructed = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'OriginalConsole.exe'))
[Array]::Resize([ref]$reconstructed, $modifiedBytes.Length)
foreach ($change in $manifest.changes) {
    $patchBytes = [Convert]::FromBase64String($change.afterBase64)
    [Array]::Copy($patchBytes, 0, $reconstructed, [int]$change.offset, $patchBytes.Length)
}
Assert-Sample ([Convert]::ToBase64String($reconstructed) -ceq [Convert]::ToBase64String($modifiedBytes)) 'manifest reconstructs exact patched bytes'
Write-Host 'PASS all intended alterations and complete patch manifest'

function Invoke-Sample([string]$Name, [string]$Arguments, [string]$ExpectedOutput) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $PSScriptRoot $Name
    $start.Arguments = $Arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit(5000)) { $process.Kill(); throw "$Name exceeded its five-second timeout" }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        Assert-Sample ($process.ExitCode -eq 0) "$Name exit code was $($process.ExitCode)"
        Assert-Sample ($stdout -ceq $ExpectedOutput) "$Name exact expected stdout"
        Assert-Sample ($stderr.Length -eq 0) "$Name empty stderr"
        Write-Host "PASS $Name $Arguments output and exit code 0"
    } finally { $process.Dispose() }
}
Invoke-Sample 'ConsoleDemo.exe' '' "PE Workshop console demo: native Win32.`r`n"
Invoke-Sample 'OriginalConsole.exe' '' "PE Workshop training marker: ORIGINAL.`r`n"
Invoke-Sample 'ModifiedConsole.exe' '' "PE Workshop training marker: MODIFIED.`r`n"
Invoke-Sample 'GuiDemo.exe' '--self-test' ''
Write-Host 'All four native sample checks passed.'
