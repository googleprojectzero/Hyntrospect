# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

param(
    [Parameter(Mandatory=$true)][string]$ConfigFile,
    [Parameter(Mandatory=$true)][string]$FuzzedDevice, 
    [string]$SeedName = "seed",
    [int]$Timeout = 2
)

if (-not (Test-Path $configFile)) {
    Write-Error "Config file not found at $ConfigFile. Aborting."
    return
}
$configFile = Resolve-Path $ConfigFile

# Make sure you have a Windows VM with chipsec installed and the ability to open an elevated session over WinRM.
$config = Get-Content -Path $configFile | ConvertFrom-Json
$VMName = $config.VMName
$CheckpointName = $config.VMCheckpointName
$HostOutputDir = $config.HostOutputDir
$username = $config.VMUsername
$ScriptPath = $PSScriptRoot
$binary = $config.Target
$debuggerPath = Resolve-Path -Path ("$ScriptPath\..\core")

if ($SeedName -notlike "seed*") {
    Write-Error "The name of the seed file should start with 'seed' for future compliance. Aborting."
    return
}

if (($VMName -eq $null) -or ($username -eq $null) -or ($CheckpointName -eq $null) -or ($HostOutputDir -eq $null) -or ($binary -eq $null)) {
    Write-Error "The config file must at least contain the fields: 'VMName', 'VMUsername', 'VMCheckpointName', 'HostOutputDir', 'Target'. Aborting."
    return
}

if ((Test-Path $HostOutputDir) -ne $true -or (Test-Path $HostOutputDir -PathType Container) -eq $false) {
    Write-Error "Invalid output directory. Please provide an existing directory. Aborting."
    return
}

if (-not (Test-Path $binary -PathType Leaf)) {
    Write-Error "Target is not a valid path. Aborting."
    return
}

if (-not (Test-Path $debuggerPath)) {
    Write-Error "DbgShell folder cannot be found. Expecting to find .\DbgShell\x64\DbgShell.exe in core. Aborting."
    return
}

$pdb = [System.IO.Path]::GetFileNameWithoutExtension($binary) + ".pdb"
if (-not (Test-Path (Join-Path "C:\Symbols\" $pdb))) {
    Write-Warning "$pdb not found in C:\Symbols. The symbols will need to be pulled from the network." 
}

$Error.Clear()
Get-VM -Name $VMName -ErrorAction SilentlyContinue
if ($Error.Count -ne 0) {
    Write-Error "The VM Name is invalid or this PowerShell session is not elevated. Aborting."
    return
}
if ((Get-VMSnapshot -VMName $VMName | Where Name -eq $CheckpointName) -eq $null) {
    Write-Error "The VM Checkpoint name is invalid. Aborting."
    return
}

Push-Location
cd $debuggerPath

# Getting the credentials of the VM
Write-Host "Please enter the VM password for user $username :" 
$secpass = Read-Host -assecurestring
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($username, $secpass)

$corpus = Join-Path $HostOutputDir "corpus"
if (-not(Test-Path $corpus)) {
    Write-Host "Creating $corpus."
    mkdir $corpus > $null
}
$seedfile = Join-Path $corpus $SeedName
Write-Host "The output file will be: $seedfile."

Write-Host "Resetting the VM."
Restore-VMSnapshot -VMName $VMName -Name $CheckpointName -Confirm:$false 
# Checks that the VM is up
if ((Get-VM -Name $VMName).State -ne "Running") {
    Start-VM -Name $VMName
}

$s = New-PSSession -VMName $VMName -Credential $creds 

Write-Host "Recording activity for the next $timeout minutes. If possible, generate as much activity as possible for device $FuzzedDevice."
$timer = [System.Diagnostics.Stopwatch]::StartNew()

$debuggerScript = Join-Path $debuggerPath "debugger-seed.ps1"
$dpid = (Start-Process -FilePath .\DbgShell\x64\DbgShell.exe -PassThru -ArgumentList "$debuggerScript ""$configfile"" ""$seedfile"" ""$FuzzedDevice"" ").Id


while ($timer.Elapsed.Minutes -lt $Timeout) {
}

Stop-Process -Id $dpid

Pop-Location