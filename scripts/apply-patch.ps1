param(
    [string]$PatchFile,
    [switch]$Check,
    [switch]$Index,
    [switch]$ThreeWay
)

$gitArgs = @('apply', '--whitespace=nowarn')

if ($Check) {
    $gitArgs += '--check'
}

if ($Index) {
    $gitArgs += '--index'
}

if ($ThreeWay) {
    $gitArgs += '--3way'
}

if ($PatchFile) {
    if (-not (Test-Path $PatchFile)) {
        Write-Error "Patch file not found: $PatchFile"
        exit 1
    }

    $gitArgs += $PatchFile
    & git @gitArgs
    exit $LASTEXITCODE
}

$tmp = [IO.Path]::GetTempFileName()
try {
    $inputText = [Console]::In.ReadToEnd()
    [IO.File]::WriteAllText($tmp, $inputText, [Text.UTF8Encoding]::new($false))

    $gitArgs += $tmp
    & git @gitArgs
    exit $LASTEXITCODE
}
finally {
    Remove-Item $tmp -ErrorAction SilentlyContinue
}