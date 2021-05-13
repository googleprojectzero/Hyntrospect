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
    [Parameter(Mandatory=$true)][string]$configfile,
    [Parameter(Mandatory=$true)][string]$bpList,
    [Parameter(Mandatory=$true)][string]$binaryname,
    [Parameter(Mandatory=$true)][string]$hostTime,
    [Parameter(Mandatory=$true)][string]$vmTime
)

$config = Get-Content -Path $configFile | ConvertFrom-Json
$VMName = $config.VMName
$HostOutputDir = $config.HostOutputDir
$ScriptPath = $PSScriptRoot
$VirtualDiskType = $config.VirtualDiskType
$username = $config.VMUsername
$password = $config.VMPassword

$helper = Join-Path $ScriptPath helper.psm1
Import-Module $helper -Force

$secpass = ConvertTo-SecureString -String $password -AsPlainText -Force
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($username, $secpass)

$hostTime = [DateTime]::Parse($hostTime)
$vmTime = [DateTime]::Parse($vmTime)

$vmid =  (Get-VM -Name $VMName | select -ExpandProperty "vmid").Guid
$vmwpPid = Get-Process -Name "vmwp" -IncludeUserName | Where-Object {$_.Username -match $vmid} | select -ExpandProperty "Id"

Connect-Process -Id $vmwpPid
$binarybase = (lm $binaryname).BaseAddress

[System.Collections.ArrayList]$blocks = Get-Content $bpList

Write-Output "Setting the breakpoints. That operation can take a long time depending on the size of the list (~sec to hour)."
foreach ($addr in $blocks) {
    $addr = $binarybase + $addr
    $addrStr = "{0:x}" -f $addr
    bp $addrStr > $null
}

# Signals the main script that the VM is ready for the tests
$debuggerReady = Join-Path $scriptPath "debugger-ready"
Set-Content -Value "" -Path $debuggerReady

Write-Output "Starting the execution."
while ($true) {
    g

    $r = r
    $bp =  $r.Rip.Value - $binarybase
    # conversion to string
    $bp = "0x"+"{0:x}" -f $bp
   
    if ($blocks.Contains($bp)) {
        $blocks.Remove($bp)
        Write-Output "New path open at $bp." 
        Set-Content -Value $blocks -Path $bpList
        # need to reset to be able to delete it
        (bp ("{0:x}" -f $r.Rip.Value)).Id | bc
    } else { 

        $hold = Join-Path $PSScriptRoot "on-hold"
        "Debugger process handling a crash." > $hold

        $crashDir = New-CrashReport -ConfigFile $configFile -mini

        Write-Warning "Unexpected break at $bp :) Creating a report in $crashDir"

        $report = Join-Path $crashDir "report.txt"
        $k = k
        $r = r
        Add-Content -Value "Unexpected break`r`nRegisters:`r`n$r`r`n`r`nStack:`r`n$k" -Path $report

        # Collects the host logs.
        Write-Host("Collecting the logs on the host")
        Get-HostEventLogs -startTime $hostTime -CrashDir $crashDir

        Write-Host "The VM will now reboot to collect logs through the monitoring process. Please type enter to let it go..."
        Read-Host | Out-Null
        "" > $hold
        break
    }
}
Write-Host "Letting go."
g