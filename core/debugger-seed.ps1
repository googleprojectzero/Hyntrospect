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
    [Parameter(Mandatory=$true)][string]$seedfile,
    [Parameter(Mandatory=$true)][string]$device
)

$config = Get-Content -Path $configFile | ConvertFrom-Json
$VMName = $config.VMName
$binary = $config.Target
$IOPortRead = $config.IOPortRead
$IOPortWrite = $config.IOPortWrite

$ScriptPath = $PSScriptRoot
$accessSizes = @(1, 2, 4) 
 
$helper = Join-Path $ScriptPath helper.psm1
Import-Module $helper -Force

$vmid =  (Get-VM -Name $VMName | select -ExpandProperty "vmid").Guid
$vmwpPid = Get-Process -Name "vmwp" -IncludeUserName | Where-Object {$_.Username -match $vmid} | select -ExpandProperty "Id"

Connect-Process -Id $vmwpPid

ide -Command '.sympath+ c:\symbols'
ide -Command '.sympath+ https://msdl.microsoft.com/download/symbols'
ide -Command '.symfix+ c:\symbols'
ide -Command '.reload /f'

$readHandler = [System.IO.Path]::GetFileNameWithoutExtension($binary) + "!$device::NotifyIOPortRead" 
$writeHandler = [System.IO.Path]::GetFileNameWithoutExtension($binary) + "!$device::NotifyIOPortWrite" 

$addrRead = (x $readHandler).Address
$addrWrite =  (x $writeHandler).Address

bp -Address $addrRead -command $null
bp -Address $addrWrite -command $null

$index = 0

while ($true) {
    g
    $r = r
    $ioport = $r.Rdx.Value
    $accessSize = $r.R8.Value

    # read
    $k = k

    # Update at every round in case the process crashes
    $fileStream = [System.IO.File]::OpenWrite($seedfile)
    $fileStream.Position = $index

    if ($k[1] -match 'NotifyIoPortRead') {
        $ioindex = $IOPortRead.IndexOf([Convert]::ToInt32($ioport))
        if ($ioindex -eq -1) {
            Write-Host "Unlisted IO port value: $ioport" -ForegroundColor Red
            Read-Host "INSTRUCTIONS: The IO port list needs to be fixed in the config file (+$ioport in the IOPortRead list). The generation of the seed needs to then be restarted. Please press enter now."
        } else {
            $fileStream.WriteByte(0)
            $fileStream.WriteByte($ioindex)
            $fileStream.WriteByte($accessSizes.IndexOf([Convert]::ToInt32($accessSize)))
            $index += 3
        }
    } else {
        $data = $r.R9.Value
        $ioindex = $IOPortWrite.IndexOf([Convert]::ToInt32($ioport))
        if ($ioindex -eq -1) {
            Write-Host "Unlisted IO port value: $ioport" -ForegroundColor Red
            Read-Host "INSTRUCTIONS: The IO port list needs to be fixed in the config file (+$ioport in the IOPortWrite list). The generation of the seed needs to then be restarted. Please press enter now."
        } else {
            $fileStream.WriteByte(1)
            $fileStream.WriteByte($ioindex)
            $fileStream.WriteByte($accessSizes.IndexOf([Convert]::ToInt32($accessSize)))
            $bytes = [System.BitConverter]::GetBytes($data)
            if ($accessSize -eq 1) {
                $fileStream.WriteByte($data)
                $index += 4
            } elseif ($accessSize -eq 2) {
                $bytes = [System.BitConverter]::GetBytes([Convert]::ToInt16($data))
                $fileStream.Write($bytes, 0, $bytes.Count)
                $index += 5
            } elseif ($accessSize -eq 4) {
                $bytes = [System.BitConverter]::GetBytes([Convert]::ToInt32($data))
                $fileStream.Write($bytes, 0, $bytes.Count)
                $index += 7
            } else {
                Write-Host "Weird data value"
                Write-Host "$r"
                Write-Host "$k"
                Read-Host
            }
        }
    }
    $fileStream.Close()
}