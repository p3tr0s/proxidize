<#
  Downloads WinDivert (signed driver + DLL) into third_party\WinDivert\x64.
  WinDivert is dual-licensed LGPLv3 / GPLv2: https://github.com/basil00/WinDivert
#>
param(
    [string]$Version = "2.2.2",
    [string]$Destination = (Join-Path $PSScriptRoot "..\third_party\WinDivert")
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$dest = [System.IO.Path]::GetFullPath($Destination)
$x64 = Join-Path $dest 'x64'
if ((Test-Path (Join-Path $x64 'WinDivert.dll')) -and (Test-Path (Join-Path $x64 'WinDivert64.sys'))) {
    Write-Host "WinDivert already present in $x64"
    exit 0
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$url = "https://github.com/basil00/WinDivert/releases/download/v$Version/WinDivert-$Version-A.zip"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("windivert-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    $zip = Join-Path $tmp 'windivert.zip'
    Write-Host "Downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $tmp -Force

    $sys = Get-ChildItem -Path $tmp -Recurse -Filter 'WinDivert64.sys' |
        Where-Object { $_.Directory.Name -eq 'x64' } |
        Select-Object -First 1
    if (-not $sys) {
        throw "WinDivert64.sys (x64) was not found in the archive."
    }

    New-Item -ItemType Directory -Force -Path $x64 | Out-Null
    Copy-Item -Path (Join-Path $sys.Directory.FullName 'WinDivert.dll') -Destination $x64 -Force
    Copy-Item -Path $sys.FullName -Destination $x64 -Force

    $root = $sys.Directory.Parent.FullName
    foreach ($item in @('LICENSE', 'README', 'README.md', 'VERSION', 'include')) {
        $path = Join-Path $root $item
        if (Test-Path $path) {
            Copy-Item -Path $path -Destination $dest -Recurse -Force
        }
    }

    Write-Host "WinDivert $Version installed to $x64"
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
