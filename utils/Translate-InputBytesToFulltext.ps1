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
    [Parameter(Mandatory=$true)][string]$InputFile
)

$helper = "$PSScriptRoot/../core/helper.psm1"
if (-not (Test-Path $helper)) {
    Write-Error "Helper not found. This file should be in 'utils', aside with 'core', which should contain 'helper.psm1'. Aborting."
    return
}
Import-Module $helper -Force

$config = Get-Content -Path $ConfigFile | ConvertFrom-Json
$IOPortRead = $config.IOPortRead
$IOPortWrite = $config.IOPortWrite

$inputbytes = Get-Content $InputFile -Encoding Byte
$inputfilelen = $inputbytes.Length
$offset = 0
# Variable for the exclusion list
$ps2Command = $false 

while($offset -lt $inputfilelen) {
    $bytes = "" 
    ($offset, $byte) = Consume-Bytes -bytes $inputbytes -offset $offset -numBytes 1 -filelen $inputfilelen
    $action = $byte % 2 # $action = 0 -> read, $action = 1 -> write 
    $bytes += '0x'+ '{0:x}'-f $byte + " "

    ($offset, $byte) = Consume-Bytes -bytes $inputbytes -offset $offset -numBytes 1 -filelen $inputfilelen
    $bytes += '0x'+ '{0:x}'-f $byte + " "

    if ($action -eq 0) {
        $ioport = $IOPortRead[$byte % $IOPortRead.length]
    } else {
        $ioport = $IOPortWrite[$byte % $IOPortWrite.length]
    }
    $x_ioport = '0x'+ '{0:x}'-f $ioport
       
    ($offset, $byte) = Consume-Bytes -bytes $inputbytes -offset $offset -numBytes 1 -filelen $inputfilelen
    $numbytes = @(1, 2, 4)[$byte % 3]
    $bytes += '0x'+ '{0:x}'-f $byte + " "

    if ($action -eq 1) {
        ($offset, $value) = Consume-Bytes -bytes $inputbytes -offset $offset -numBytes $numbytes -filelen $inputfilelen
        $x_value = '0x'+ '{0:x}' -f $value
        $bytes += "$x_value "
    }

    if (($ioport -eq 0x64) -and ($action -eq 1) -and ($value -eq 0xd1)) {
        $ps2Command = $true
    }

    switch ($action) { 
        0 { # read
            Write-Output "$bytes -> R $x_ioport $numbytes"              
        }
        1 { # write
            if (($ioport -eq 0x64) -and ($value -ge 0xF0)) {
                Write-Output "$bytes -> W $x_ioport $numbytes $x_value - Skipped - PS2 reset on 0x64 high values." 
            } elseif (($ioport -eq 0x92) -and (($value -band 1) -eq 1)) {
                Write-Output "$bytes -> W $x_ioport $numbytes $x_value - Skipped - Fast A20 reset." 
            } elseif ($ps2Command -and ($ioport -eq 0x60) -and (($value -band 1) -eq 1) -and (($value -band 2) -eq 0)) {
                Write-Output "$bytes -> W $x_ioport $numbytes $x_value - Skipped - A20 gate case via PS2." 
            } elseif ($ps2Command -and ($ioport -eq 0x60) -and (($value -band 1) -eq 0)) {
                Write-Output "$bytes -> W $x_ioport $numbytes $x_value - Skipped - PS2 system reset." 
            } else {
                Write-Output "$bytes -> W $x_ioport $numbytes $x_value"
            }
        }
    }
}
    
