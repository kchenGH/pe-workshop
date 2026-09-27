param([switch]$SelfContained)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    $sampleBuild = Join-Path $PSScriptRoot '../Samples/build.ps1'
    if (-not (Test-Path -LiteralPath $sampleBuild)) { throw 'Samples/build.ps1 is required beside PE-Editor for the comparison checks.' }
    & $sampleBuild
    dotnet run --project tests/PeWorkshop.Tests -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Core tests failed.' }
    $contained = if ($SelfContained) { 'true' } else { 'false' }
    dotnet publish src/PeWorkshop.App -c Release -r win-x64 --self-contained $contained -o artifacts/PEWorkshop
    if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
    $smokeDirectory = Join-Path $PSScriptRoot 'artifacts/smoke'
    $app = Join-Path $PSScriptRoot 'artifacts/PEWorkshop/PEWorkshop.exe'
    $process = Start-Process -FilePath $app -ArgumentList @('--smoke-test', ('"' + $smokeDirectory + '"')) -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(60000)) { $process.Kill(); throw 'UI smoke test timed out after 60 seconds.' }
    if ($process.ExitCode -ne 0) { throw "UI smoke test failed. See $smokeDirectory/result.txt" }
    Get-Content -LiteralPath (Join-Path $smokeDirectory 'result.txt')
    Write-Output "Built: $app"
}
finally { Pop-Location }
