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
    [Parameter(Mandatory=$true)][string]$configFile,
    [Parameter(Mandatory=$true)][DateTime]$hostTime,
    [Parameter(Mandatory=$true)][DateTime]$vmTime,
    [Parameter(Mandatory=$false)][string]$tmpFolder
)

$config = Get-Content -Path $configFile | ConvertFrom-Json
$VMName = $config.VMName
$HostOutputDir = $config.HostOutputDir
$username = $config.VMUsername
$password = $config.VMPassword
$VirtualDiskType = $config.VirtualDiskType

$helper = Join-Path $PSScriptRoot helper.psm1
Import-Module $helper -Force

# This file monitors the VM. Lifetime: consumption of one random input file
#while(Check-VMSanity -VMName $VMName)
#{
    #If everything is normal, the process will be killed while in that loop
#}
$ticks = (Get-VM -Name $VMName).Uptime.Ticks
while ((Get-VM -Name $VMName).State -eq "Running" -and $ticks -le (Get-VM -Name $VMName).Uptime.Ticks) { 
    $ticks = (Get-VM -Name $VMName).Uptime.Ticks
    Start-Sleep -Seconds 1
}

# Gets here if the VM has met an issue
$vm = Get-VM -Name $VMName
$state = $vm.State
$status = $vm.Status
Write-Error "VM not running. State: $state, status: $status."

if ($tmpFolder) {
    $crashDir = New-CrashReport -ConfigFile $ConfigFile -tmp $tmpFolder
} else {
    $crashDir = New-CrashReport -ConfigFile $ConfigFile
}

$secpass = ConvertTo-SecureString -String $password -AsPlainText -Force
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($username, $secpass)

Collect-CrashInfo -VMName $VMName -creds $creds -crashDir $crashDir -hostTime $hostTime -vmTime $vmTime -err $Error[0]

RecoverFrom-Crash -monitoring