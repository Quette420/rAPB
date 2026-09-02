[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [ValidateSet("Win32", "x64")]
    [string]$DistrictPlatform = "Win32",

    [switch]$NoStopProcesses
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Find-EmulatorRoot {
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    if (-not $scriptDir) {
        $scriptDir = (Get-Location).Path
    }

    $candidates = @(
        $scriptDir,
        (Join-Path $scriptDir "Emulator"),
        (Split-Path -Parent $scriptDir),
        (Join-Path (Split-Path -Parent $scriptDir) "Emulator")
    ) | Select-Object -Unique

    foreach ($dir in $candidates) {
        if ($dir -and (Test-Path (Join-Path $dir "ApbEmu.sln"))) {
            return (Resolve-Path $dir).Path
        }
    }

    throw @"
Cannot find Emulator\ApbEmu.sln.

Put this script either:
  1) in the rAPB repository root, or
  2) directly in rAPB\Emulator

Then run it again.
"@
}

function Find-MSBuild {
    $cmd = Get-Command "MSBuild.exe" -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $vswhereCandidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"),
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\Installer\vswhere.exe")
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($vswhere in $vswhereCandidates) {
        $found = & $vswhere `
            -latest `
            -products * `
            -requires Microsoft.Component.MSBuild `
            -find "MSBuild\**\Bin\MSBuild.exe" 2>$null |
            Select-Object -First 1

        if ($found -and (Test-Path $found)) {
            return $found
        }
    }

    throw @"
MSBuild.exe was not found.

Install Visual Studio with:
  - .NET desktop development
  - Desktop development with C++
  - MSBuild

DistrictServer in this repository also requires the C++ toolset configured
by DistrictServer.vcxproj.
"@
}

function Invoke-CSharpBuild {
    param(
        [Parameter(Mandatory=$true)][string]$Project,
        [Parameter(Mandatory=$true)][string]$OutputDir
    )

    $name = [IO.Path]::GetFileName($Project)
    Write-Step "Building $name ($Configuration / AnyCPU)"

    $args = @(
        $Project,
        "/nologo",
        "/m",
        "/t:Rebuild",
        "/p:Configuration=$Configuration",
        "/p:Platform=AnyCPU",
        "/p:OutputPath=$OutputDir"
    )

    & $script:MSBuild @args
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed: $name (MSBuild exit code $LASTEXITCODE)"
    }
}

function Invoke-CppBuild {
    param(
        [Parameter(Mandatory=$true)][string]$Project,
        [Parameter(Mandatory=$true)][string]$OutputDir,
        [Parameter(Mandatory=$true)][string]$IntermediateDir
    )

    $name = [IO.Path]::GetFileName($Project)
    Write-Step "Building $name ($Configuration / $DistrictPlatform)"

    $args = @(
        $Project,
        "/nologo",
        "/m",
        "/t:Rebuild",
        "/p:Configuration=$Configuration",
        "/p:Platform=$DistrictPlatform",
        "/p:OutDir=$OutputDir",
        "/p:IntDir=$IntermediateDir"
    )

    & $script:MSBuild @args
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed: $name (MSBuild exit code $LASTEXITCODE)"
    }
}

$EmulatorRoot = Find-EmulatorRoot
$DeployDir = Join-Path $EmulatorRoot "APB SERVER"

$MyDbProject = Join-Path $EmulatorRoot "MyDB\MyDB.csproj"
$LobbyProject = Join-Path $EmulatorRoot "LobbyServer\LoginServer.csproj"
$WorldProject = Join-Path $EmulatorRoot "WorldServer\WorldServer.csproj"
$DistrictProject = Join-Path $EmulatorRoot "DistrictServer\DistrictServer.vcxproj"

$projects = @($MyDbProject, $LobbyProject, $WorldProject, $DistrictProject)
foreach ($project in $projects) {
    if (-not (Test-Path $project)) {
        throw "Project file not found: $project"
    }
}

if (-not (Test-Path $DeployDir)) {
    New-Item -ItemType Directory -Path $DeployDir | Out-Null
}

# These are build-time dependencies referenced by HintPath in the C# projects.
$requiredDependencies = @(
    "FrameWork.dll",
    "MySql.Data.dll"
)

foreach ($dependency in $requiredDependencies) {
    $path = Join-Path $DeployDir $dependency
    if (-not (Test-Path $path)) {
        throw "Required dependency is missing: $path"
    }
}

if (-not $NoStopProcesses) {
    Write-Step "Stopping running rAPB server processes"

    foreach ($processName in @("WorldServer", "LobbyServer", "DistrictServer")) {
        $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue
        if ($processes) {
            $processes | ForEach-Object {
                Write-Host ("Stopping {0}.exe (PID {1})" -f $processName, $_.Id)
                Stop-Process -Id $_.Id -Force
            }
        }
    }
}

$script:MSBuild = Find-MSBuild
Write-Host "MSBuild: $script:MSBuild"
Write-Host "Emulator root: $EmulatorRoot"
Write-Host "Deploy dir:    $DeployDir"

$BuildRoot = Join-Path $EmulatorRoot ".build"
$StageDir = Join-Path $BuildRoot ("stage-{0}-{1}" -f $Configuration, $DistrictPlatform)
$ObjDir = Join-Path $BuildRoot ("obj-{0}-{1}" -f $Configuration, $DistrictPlatform)

Write-Step "Preparing clean staging directory"

foreach ($dir in @($StageDir, $ObjDir)) {
    if (Test-Path $dir) {
        Remove-Item $dir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $dir | Out-Null
}

# MSBuild behaves more predictably when OutDir/OutputPath end in a slash.
$StageDirWithSlash = $StageDir.TrimEnd('\') + '\'
$DistrictObjDir = (Join-Path $ObjDir "DistrictServer").TrimEnd('\') + '\'

# Build C# first. WorldServer and LobbyServer reference MyDB.
Invoke-CSharpBuild -Project $MyDbProject -OutputDir $StageDirWithSlash
Invoke-CSharpBuild -Project $LobbyProject -OutputDir $StageDirWithSlash
Invoke-CSharpBuild -Project $WorldProject -OutputDir $StageDirWithSlash

# Build the native district server separately so its Win32/x64 platform
# does not get confused with C# "Any CPU" solution configurations.
Invoke-CppBuild `
    -Project $DistrictProject `
    -OutputDir $StageDirWithSlash `
    -IntermediateDir $DistrictObjDir

Write-Step "Validating build output"

$requiredOutputs = @(
    "WorldServer.exe",
    "LobbyServer.exe",
    "DistrictServer.exe",
    "MyDB.dll"
)

foreach ($file in $requiredOutputs) {
    $source = Join-Path $StageDir $file
    if (-not (Test-Path $source)) {
        throw "Expected build output was not created: $source"
    }
    Write-Host "OK: $file"
}

Write-Step "Deploying fresh binaries to APB SERVER"

# Only these generated files are replaced.
# Configs, Logs and hand-provided dependencies are intentionally preserved.
$deployPatterns = @(
    "WorldServer.exe",
    "WorldServer.exe.config",
    "WorldServer.pdb",
    "LobbyServer.exe",
    "LobbyServer.exe.config",
    "LobbyServer.pdb",
    "DistrictServer.exe",
    "DistrictServer.pdb",
    "MyDB.dll",
    "MyDB.pdb"
)

foreach ($name in $deployPatterns) {
    $source = Join-Path $StageDir $name
    if (Test-Path $source) {
        $destination = Join-Path $DeployDir $name
        Copy-Item $source $destination -Force
        Write-Host "Copied: $name"
    }
}

Write-Step "Verifying deployed binaries by SHA-256"

$verificationFailed = $false

foreach ($name in $requiredOutputs) {
    $source = Join-Path $StageDir $name
    $destination = Join-Path $DeployDir $name

    $sourceHash = (Get-FileHash $source -Algorithm SHA256).Hash
    $destinationHash = (Get-FileHash $destination -Algorithm SHA256).Hash
    $item = Get-Item $destination

    $ok = $sourceHash -eq $destinationHash
    if (-not $ok) {
        $verificationFailed = $true
    }

    [PSCustomObject]@{
        File = $name
        Match = $ok
        Size = $item.Length
        LastWriteTime = $item.LastWriteTime
        SHA256 = $destinationHash
    } | Format-List
}

if ($verificationFailed) {
    throw "Deployment verification failed: at least one copied file has a different SHA-256 hash."
}

Write-Host ""
Write-Host "BUILD + DEPLOY SUCCESS" -ForegroundColor Green
Write-Host ""
Write-Host "Fresh binaries are here:"
Write-Host "  $DeployDir"
Write-Host ""
Write-Host "Start them from that directory, for example:"
Write-Host "  cd `"$DeployDir`""
Write-Host "  .\WorldServer.exe"
Write-Host "  .\DistrictServer.exe"
Write-Host ""
Write-Host "Configs, Logs, FrameWork.dll, MySql.Data.dll and libmysql.dll were preserved."
