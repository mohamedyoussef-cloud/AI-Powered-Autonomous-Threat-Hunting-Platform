param(
    [string]$SplunkPath = "",
    [string]$InventoryPath = "",
    [string]$OutputDir = "",
    [string]$RunLog = ""
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$WorkspaceRoot = Split-Path -Parent $ProjectRoot

$ProfilingDir = Join-Path `
    $WorkspaceRoot `
    "datasets\processed\botsv3\profiling"

if (-not $InventoryPath) {
    $InventoryPath = Join-Path `
        $ProfilingDir `
        "sourcetype_indexed_inventory.csv"
}

if (-not $OutputDir) {
    $OutputDir = Join-Path `
        $ProfilingDir `
        "field_profiles"
}

if (-not $RunLog) {
    $RunLog = Join-Path `
        $ProfilingDir `
        "field_profile_run_log.csv"
}

# Resolve Splunk without relying on a machine-specific path.
if (-not $SplunkPath) {

    if ($env:SPLUNK_HOME) {

        $Candidate = Join-Path `
            $env:SPLUNK_HOME `
            "bin\splunk.exe"

        if (Test-Path -LiteralPath $Candidate) {
            $SplunkPath = $Candidate
        }
    }

    if (-not $SplunkPath) {

        $Command = Get-Command `
            "splunk.exe" `
            -ErrorAction SilentlyContinue

        if (-not $Command) {
            $Command = Get-Command `
                "splunk" `
                -ErrorAction SilentlyContinue
        }

        if ($Command) {
            $SplunkPath = $Command.Source
        }
    }
}

if (
    -not $SplunkPath -or
    -not (Test-Path -LiteralPath $SplunkPath)
) {
    throw @"
Splunk CLI was not found.

Supply it explicitly, for example:

.\scripts\profile_botsv3_fields.ps1 -SplunkPath "<SPLUNK_HOME>\bin\splunk.exe"

Alternatively set the SPLUNK_HOME environment variable.
"@
}

if (-not (Test-Path -LiteralPath $InventoryPath)) {
    throw "Inventory not found: $InventoryPath"
}

$Splunk = $SplunkPath

New-Item `
    -ItemType Directory `
    -Path $OutputDir `
    -Force |
Out-Null

$Inventory = @(
    Import-Csv $InventoryPath
)

if ($Inventory.Count -ne 107) {
    throw (
        "Inventory validation failed. " +
        "Expected 107 sourcetypes, found " +
        "$($Inventory.Count)."
    )
}

Write-Host "Splunk:    $Splunk"
Write-Host "Inventory: $InventoryPath"
Write-Host "Output:    $OutputDir"
Write-Host "Run log:   $RunLog"
Write-Host ""

for (
    $i = 0;
    $i -lt $Inventory.Count;
    $i++
) {

    $n = $i + 1
    $st = $Inventory[$i].sourcetype

    $safeName = (
        $st -replace '[^A-Za-z0-9._-]', '_'
    )

    $fileName = (
        "{0:D3}_{1}.csv" -f $n, $safeName
    )

    $outFile = Join-Path `
        $OutputDir `
        $fileName

    $tmpFile = "$outFile.tmp"

    # Resume-safe: skip completed profiles.
    if (Test-Path -LiteralPath $outFile) {

        try {

            $existing = @(
                Import-Csv $outFile
            )

            if ($existing.Count -gt 0) {

                Write-Host (
                    "[$n/$($Inventory.Count)] " +
                    "SKIP  $st  " +
                    "($($existing.Count) fields)"
                )

                continue
            }
        }
        catch {
            # Invalid/incomplete file:
            # rerun this sourcetype.
        }
    }

    Write-Host (
        "[$n/$($Inventory.Count)] START $st"
    )

    $escapedST = $st.Replace(
        '"',
        '\"'
    )

    if ($st -like '*AppLocker*EXE*') {

        $baseSearch = (
            'index=botsv3 earliest=0 ' +
            'sourcetype=*AppLocker* ' +
            'sourcetype=*EXE*'
        )
    }
    elseif ($st -like '*AppLocker*Packaged*') {

        $baseSearch = (
            'index=botsv3 earliest=0 ' +
            'sourcetype=*AppLocker* ' +
            'sourcetype=*Packaged*'
        )
    }
    else {

        $baseSearch = (
            "index=botsv3 " +
            "sourcetype=`"$escapedST`" " +
            "earliest=0"
        )
    }

    $spl = (
        "$baseSearch " +
        "| fieldsummary maxvals=1 " +
        "| fields field count distinct_count " +
        "is_exact numeric_count min max mean stdev"
    )

    $sw = [Diagnostics.Stopwatch]::StartNew()

    try {

        $savedEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"

        try {

            $result = & $Splunk search `
                $spl `
                -preview false `
                -output csv `
                -timeout 900 `
                -maxout 10000 `
                2>$null

            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $savedEap
        }

        if (
            $exitCode -ne 0 -or
            -not $result
        ) {
            throw (
                "Splunk CLI failed with exit code " +
                "$exitCode"
            )
        }

        $result |
            Set-Content `
                $tmpFile `
                -Encoding UTF8

        $profile = @(
            Import-Csv $tmpFile
        )

        if ($profile.Count -eq 0) {
            throw "Profile returned zero fields."
        }

        Move-Item `
            $tmpFile `
            $outFile `
            -Force

        $sw.Stop()

        $logRow = [PSCustomObject]@{
            timestamp = (
                Get-Date
            ).ToString("s")

            sequence = $n
            sourcetype = $st

            indexed_events = (
                $Inventory[$i].indexed_events
            )

            field_count = $profile.Count

            elapsed_seconds = [math]::Round(
                $sw.Elapsed.TotalSeconds,
                2
            )

            status = "SUCCESS"
            output_file = $fileName
        }

        Write-Host (
            "[$n/$($Inventory.Count)] " +
            "DONE  $st  " +
            "fields=$($profile.Count)  " +
            "seconds=$(" +
            [math]::Round(
                $sw.Elapsed.TotalSeconds,
                1
            ) +
            ")"
        )
    }
    catch {

        $sw.Stop()

        Remove-Item `
            $tmpFile `
            -Force `
            -ErrorAction SilentlyContinue

        $logRow = [PSCustomObject]@{
            timestamp = (
                Get-Date
            ).ToString("s")

            sequence = $n
            sourcetype = $st

            indexed_events = (
                $Inventory[$i].indexed_events
            )

            field_count = 0

            elapsed_seconds = [math]::Round(
                $sw.Elapsed.TotalSeconds,
                2
            )

            status = "FAILED"
            output_file = $fileName
        }

        Write-Warning (
            "[$n/$($Inventory.Count)] " +
            "FAILED $st : " +
            "$($_.Exception.Message)"
        )
    }

    if (Test-Path -LiteralPath $RunLog) {

        $logRow |
            Export-Csv `
                $RunLog `
                -NoTypeInformation `
                -Append `
                -Encoding UTF8
    }
    else {

        $logRow |
            Export-Csv `
                $RunLog `
                -NoTypeInformation `
                -Encoding UTF8
    }
}

Write-Host ""
Write-Host "BOTS v3 field profiling run finished."
