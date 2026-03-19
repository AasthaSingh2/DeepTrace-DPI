param(
    [string]$Exe = "..\build\Release\deeptrace_dpi.exe",
    [string]$Pcap = "..\data\test_dpi.pcap",
    [int]$Runs = 5,
    [string[]]$ExtraArgs = @()
)

if ($Runs -lt 1) {
    throw "Runs must be at least 1."
}

$times = @()

for ($i = 1; $i -le $Runs; $i++) {
    $output = & $Exe $Pcap @ExtraArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | ForEach-Object { $_ }
        throw "Benchmark run $i failed."
    }

    $match = $output | Select-String -Pattern 'Processing time:\s+([0-9.]+)\s+s' | Select-Object -First 1
    if (-not $match) {
        $output | ForEach-Object { $_ }
        throw "Could not find processing time in run $i output."
    }

    $time = [double]$match.Matches[0].Groups[1].Value
    $times += $time
    Write-Host ("Run {0}: {1:N6} s" -f $i, $time)
}

$average = ($times | Measure-Object -Average).Average
Write-Host ("Average runtime over {0} runs: {1:N6} s" -f $Runs, $average)
