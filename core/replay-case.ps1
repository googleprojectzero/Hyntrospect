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
    [Parameter(Mandatory=$true)][string]$reproFile, 
    [Parameter(Mandatory=$true)][string]$folder,
    [Parameter(Mandatory=$false)][System.Collections.ArrayList]$virtualdisks
)

# Please make sure you have a Windows VM with chipsec installed and the ability to open an elevated session over WinRM.
$config = Get-Content -Path $configFile | ConvertFrom-Json
$VMName = $config.VMName
$CheckpointName = $config.VMCheckpointName
$HostOutputDir = $config.HostOutputDir
$VMChipsecFilepath = $config.VMChipsecFilepath
$username = $config.VMUsername
$password = $config.VMPassword
$ScriptPath = $PSScriptRoot
$IdaPath = $config.HostIdaPath
$binary = $config.Target
$IOPortRead = $config.IOPortRead
$IOPortWrite = $config.IOPortWrite
$VirtualDiskType = $config.VirtualDiskType


# Gets the ID of the VM
$vmid =  (Get-VM -Name $VMName | select -ExpandProperty "vmid").Guid

# Loads the helper functions
$helper = Join-Path $ScriptPath helper.psm1
Import-Module $helper -Force

$secpass = ConvertTo-SecureString -String $password -AsPlainText -Force
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($username, $secpass)

# Sets error handling.
$Error.Clear()
$ErrorActionPreference = 'Continue'

# Gets the binary name without extension for the debugger
$binaryNameWithoutExtension = [io.path]::GetFileNameWithoutExtension($binary)

# Sets up the file system fuzzer when applicable
$fs = New-Object System.Collections.ArrayList
if ($virtualdisks) {
    $fs = $virtualdisks
    $fs.Insert(0, $null)
}

# Initializes local variables
$monPid = $null
$dpid = $null
$s = $null

# Resets the environment 
Write-Host "Resetting the environment"
Restore-VMSnapshot -VMName $VMName -Name $CheckpointName -Confirm:$false 

# Checks that the VM is up
if ((Get-VM -Name $VMName).State -ne "Running") {
    Start-VM -Name $VMName
}

# Sets the PS session for VM communication
$s = New-PSSession -VMName $VMName -Credential $creds 

# Gets the starting time of the host and VM - used later as a reference for the collection of the event logs.
$hostTime = Get-Date
$timestamp = Get-date -Format "yyMMdd-HHmm"
Write-Verbose("Host time: " + $hostTime) 
$vmTime = Invoke-Command -Session $s -ScriptBlock {Get-Date}

# Connects to the debugee
Write-Host "Connecting to the debuggee"
$debuggerScript = Join-Path $scriptPath "debugger-replay.ps1"
$hostTimeStr = $hostTime.GetDateTimeFormats('o')
$vmTimeStr = $vmTime.GetDateTimeFormats('o')
$dpid = (Start-Process -FilePath .\DbgShell\x64\DbgShell.exe -PassThru -ArgumentList "$debuggerScript ""$configfile"" ""$binaryNameWithoutExtension"" ""$hostTimeStr"" ""$vmTimeStr"" ").Id

# Starts the monitoring process for that new round
Write-Host "Starting the monitoring process"
$monitoringScriptPath = Join-Path $ScriptPath "vm-monitoring.ps1"
$moncommand = "-configFile ""$configFile"" -hostTime ""$hostTime"" -vmTime ""$vmTime"" -tmpFolder ""$folder"" "
$monPid = Start-HelperProcess -script $monitoringScriptPath -commandline $moncommand

# Consumes the input file.
$inputbytes = Get-Content $reproFile -Encoding Byte
$inputfilelen = $inputbytes.Length
Write-Host "Replaying $reproFile"

# Executes the payload on the VM. One iteration per virtual disk attached, only 1 if not fuzzing virtual disks.
do {
    # Input file offset
    $offset = 0

    # Variable for the exclusion list
    $ps2Command = $false 

    # If fuzzing the file system, sets the file system
    if ($VirtualDiskType) {

        $fsfile = $fs[0]

        if ($VirtualDiskType.GetType().Name -eq "string") {
            if ($VirtualDiskType -eq "vfd") {
                Set-VMFloppyDiskDrive -VMName $VMName -Path $fsfile
            } elseif ($VirtualDiskType -eq "iso") {
                Set-VMDvdDrive -VMName $VMName -Path $fsfile 
            } elseif ($VirtualDiskType -eq "vhd") {
                # Set-VMHardDiskDrive -VMName $VMName -Path $fsfile
                Set-VMHardDiskDriveForFuzzing -VMName $VMName -Path $fsfile -s $s
            } else {
                Write-Warning "`tDid not recognize the format of $fsfile."
            }
        } else { # case of multiple fuzzed formats
            if ($VirtualDiskType.Contains("vfd") -and (($fsfile -eq $null) -or ([io.path]::GetExtension($fsfile) -eq ".vfd"))) {
                Set-VMFloppyDiskDrive -VMName $VMName -Path $fsfile
            } 
            if ($VirtualDiskType.Contains("iso") -and (($fsfile -eq $null) -or ([io.path]::GetExtension($fsfile) -eq ".iso"))) {
                Set-VMDvdDrive -VMName $VMName -Path $fsfile 
            }
            if ($VirtualDiskType.Contains("vhd") -and (($fsfile -eq $null) -or ([io.path]::GetExtension($fsfile) -eq ".vhd"))) {
                # Set-VMHardDiskDrive -VMName $VMName -Path $fsfile
                Set-VMHardDiskDriveForFuzzing -VMName $VMName -Path $fsfile -s $s
            }
        }

        if ($fsfile) {
            Write-Host "`tAttached $fsfile."
        } else {
            Write-Host "`tNo virtual disk attached."
        }
    }

    # Each iteration in that loop corresponds to one command sent
    while($offset -lt $inputfilelen) {
        ($offset, $byte) = Consume-Bytes -bytes $inputbytes -offset $offset -numBytes 1 -filelen $inputfilelen
        $action = $byte % 2 # $action = 0 -> read, $action = 1 -> write 

        ($offset, $byte) = Consume-Bytes -bytes $inputbytes -offset $offset -numBytes 1 -filelen $inputfilelen
        if ($action -eq 0) {
            $ioport = $IOPortRead[$byte % $IOPortRead.length]
        } else {
            $ioport = $IOPortWrite[$byte % $IOPortWrite.length]
        }
        $x_ioport = '0x'+ '{0:x}'-f $ioport
       
        ($offset, $byte) = Consume-Bytes -bytes $inputbytes -offset $offset -numBytes 1 -filelen $inputfilelen
        $numbytes = @(1, 2, 4)[$byte % 3]

        if ($action -eq 1) {
            ($offset, $value) = Consume-Bytes -bytes $inputbytes -offset $offset -numBytes $numbytes -filelen $inputfilelen
            $x_value = '0x'+ '{0:x}' -f $value
            Write-Verbose "W $x_ioport $numbytes $x_value, next index: $offset" 
        } else {
            Write-Verbose "R $x_ioport $numbytes,  next index: $offset"
        }

        # Exclusion list lists
        if (($ioport -eq 0x64) -and ($action -eq 1) -and ($value -ge 0xF0)) {
            Write-Verbose "Skipping, resuming at index $offset" 
            continue
        }
        if (($ioport -eq 0x92) -and ($action -eq 1) -and (($value -band 1) -eq 1)) {
            Write-Verbose "Skipping, resuming at index $offset" 
            continue
        }
        # A20 gate
        if (($ioport -eq 0x64) -and ($action -eq 1) -and ($value -eq 0xd1)) {
            $ps2Command = $true
        }
        if ($ps2Command -and ($ioport -eq 0x60) -and ($action -eq 1) -and (($value -band 1) -eq 1) -and (($value -band 2) -eq 0)) {
            Write-Verbose "W $x_ioport $numbytes $x_value - Skipping, resuming at index $offset" 
            continue
        }
        if ($ps2Command -and ($ioport -eq 0x60) -and ($action -eq 1) -and (($value -band 1) -eq 0)) {
            Write-Verbose "W $x_ioport $numbytes $x_value - Skipping, resuming at index $offset" 
            continue
        }

        switch ($action) { 
            0 { # read
                $command = Set-IoCommand -VMChipsecFilepath $VMChipsecFilepath -port $ioport -len $numbytes -value $null                
            }
            1 { # write
                $command = Set-IoCommand -VMChipsecFilepath $VMChipsecFilepath -port $ioport -len $numbytes -value $value
            }
        }

        # Waiting until the VM runs again (until the debugger lets it go)
        do {
            $Error.Clear()
            Get-VM $VMName -ErrorAction SilentlyContinue > $null
        } while ($Error.Count -ne 0)
        
        Invoke-Command -Session $s -ScriptBlock {param($command) iex -command $command} -ArgumentList @($command) | Out-Null
                 
    } 

    # If fuzzing the file system, sets the file system accordingly
    if ($VirtualDiskType) {
        $fs.Remove($fsfile)
        if ($fsfile) {
            if (([System.IO.FileInfo]$fsfile).Extension -eq ".vfd") {
                Set-VMFloppyDiskDrive -VMName $VMName -Path $null
            } elseif (([System.IO.FileInfo]$fsfile).Extension -eq ".iso") {
                Set-VMDvdDrive -VMName $VMName -Path $null
            } elseif (([System.IO.FileInfo]$fsfile).Extension -eq ".vhd") {
                Unset-VMHardDiskDriveForFuzzing -VMName $VMName -Path $fsfile -s $s
                # Remove-VMHardDiskDrive -VMName $VMName -Path $fsfile
            } else {}
        }
    }
} while ($fs.Count -ne 0)


# Shuts down
Write-Host "Done."
Write-Host "Killing the monitoring and the debugging process."

Remove-PSSession $s
Stop-Process -Id $monPid -Force
if (-not (Get-Process -Id $dpid)) {
    Write-Warning "Debug process already killed!!"
}
Stop-Process -Id $dpid -Force