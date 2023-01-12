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
    [Parameter(Mandatory=$true)][string]$configFile
)

# Please make sure you have a Windows VM with chipsec installed and the ability to open an elevated session over WinRM.
$config = Get-Content -Path $configFile | ConvertFrom-Json
$VMName = $config.VMName
$CheckpointName = $config.VMCheckpointName
$HostOutputDir = $config.HostOutputDir
$VMChipsecFilepath = $config.VMChipsecFilepath
$MaxInputSize = $config.MaxInputSize
$MinInputSize = $config.MinInputSize
$username = $config.VMUsername
$password = $config.VMPassword
$ScriptPath = $PSScriptRoot
$IdaPath = $config.HostIdaPath
$binary = $config.Target
$IOPortRead = $config.IOPortRead
$IOPortWrite = $config.IOPortWrite
$MaxMutationRate = $config.MaxMutationRate
$VirtualDiskType = $config.VirtualDiskType

# The mutation rate will be modified over time.
$env:mutationRate = 0.01 
# The fuzzer works with 2 phases: a slow convergence at the beginning, an accelerated one once the coverage starts plateauing 
$env:accelerated = $null

if ($MaxMutationRate -eq $null) {
    $MaxMutationRate = 0.3
}
if ($MaxInputSize -eq $null) {
    $MaxInputSize = 4096
}
if ($MinInputSize -eq $null) {
    $MinInputSize = 100
}

# Gets the credentials of the VM
$secpass = ConvertTo-SecureString -String $password -AsPlainText -Force
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($username, $secpass)

# Gets the ID of the VM
$vmid =  (Get-VM -Name $VMName | select -ExpandProperty "vmid").Guid

# Loads the helper functions
$helper = Join-Path $ScriptPath helper.psm1
Import-Module $helper -Force -WarningAction SilentlyContinue

# Cleaning in case the previous execution was stopped in an unstable state
$debuggerReady = Join-Path $scriptPath "debugger-ready"
if (Test-Path $debuggerReady) {
    rm $debuggerReady
}
$hold = Join-Path $PSScriptRoot "on-hold"
if (Test-Path $hold) {
    rm $hold
}


# Computes the hash of the target binary for versioning
$hash = (Get-FileHash $binary -Algorithm MD5).Hash

# Sets error handling.
$Error.Clear()
$ErrorActionPreference = 'Continue'

# If the breakpoints list does not exist, initializes it
$binaryNameWithoutExtension = [io.path]::GetFileNameWithoutExtension($binary)
$bpList = Join-Path $HostOutputDir "breakpoints-$binaryNameWithoutExtension-$hash.txt"
if (-not (Test-Path $bpList)) {
    Write-Warning "Initializing the bp list for $binaryNameWithoutExtension version $hash."
    $bpscript = Join-Path $ScriptPath "findPatchPoints.py"
    $idb = Join-Path $HostOutputDir "$binaryNameWithoutExtension.i64"
    Init-BreakpointList -ida $IdaPath -idb $idb -bpscript $bpscript -bpList $bpList -binary $binary
}
$bpListBck = Join-Path $HostOutputDir "breakpoints-$binaryNameWithoutExtension-$hash-init.txt"

# Reads the bp list 
Copy-Item $bpList $bpListBck
$blocks = Get-Content $bpList

# Starts the input generator
$inputGeneratorPath = Join-Path $ScriptPath "input-generator.ps1"
$inputcommand = "-HostOutputDir ""$HostOutputDir""  -maxInputSize $MaxInputSize -minInputSize $MinInputSize"
$inputGenPid = Start-HelperProcess -script $inputGeneratorPath -commandline $inputcommand
$corpus = Join-Path $HostOutputDir "corpus"
$tmp = Join-Path $HostOutputDir "tmp"
mkdir $tmp -ErrorAction SilentlyContinue | Out-Null

# Sets up the file system fuzzer when applicable
$fs = New-Object System.Collections.ArrayList
if ($VirtualDiskType) {
    $fsCorpus = Join-Path $HostOutputDir "fscorpus"
    if (-not (Test-Path $fsCorpus)) {
        mkdir $fsCorpus | Out-Null
    }
    $fsGeneratorPath = Join-Path $ScriptPath "fs-generator.ps1"
    if ($VirtualDiskType.GetType().Name -eq "String") {
        $fsTemplate = Join-Path $fsCorpus "template.$VirtualDiskType"
        if (Test-Path -Path "..\data\template.$VirtualDiskType") {
            Copy-Item "..\data\template.$VirtualDiskType" $fsCorpus
        }
        else {
            New-Item -Path $fsTemplate -Value "Test" -ItemType File -Force > $null
        }
        $fscommand = "-HostOutputDir ""$HostOutputDir"" -VirtualDiskType $VirtualDiskType"
        $fsGenPid = Start-HelperProcess -script $fsGeneratorPath -commandline $fscommand
    } else {
        $fsTemplate = New-Object System.Collections.ArrayList
        $fscommands = New-Object System.Collections.ArrayList
        foreach ($format in $VirtualDiskType) {
            if (Test-Path -Path "..\data\template.$VirtualDiskType") {
                Copy-Item "..\data\template.$format" $fsCorpus
            }
            else {
                New-Item -Path (Join-Path $fsCorpus "template.$format") -Value "Test" -ItemType File -Force > $null
            }
            $fsTemplate.Add((Join-Path $fsCorpus "template.$format")) > $null
            $fscommand = "-HostOutputDir ""$HostOutputDir"" -VirtualDiskType $format"
            $fscommands.Add($fscommand) > $null
            $fsGenPid = Start-HelperProcess -script $fsGeneratorPath -commandline $fscommand           
        }
    }
}

# Prepares for a pre-coverage without starting the fuzzer if there are seed files and not yet other corpus files (which would mean previous runs) 
if (-not (ls $corpus | Where Name -Like "corpus*")) {
    $seeds_ = ls $corpus | Where Name -Like "seed*" 
    # Dealing with singleton (related to PowerShell types)
    if ($seeds_.GetType().Name -eq "FileInfo") {
        $seeds = New-Object System.Collections.ArrayList
        $seeds.Add($seeds_)
    }
    [System.Collections.ArrayList]$seeds = $seeds_
} else {
    $seeds = New-Object System.Collections.ArrayList
}

# Initializes local variables
$monPid = $null
$dpid = $null
$s = $null
$idleloopCount = 0

# Each iteration in that loop corresponds to a new random input stream 
while ($true) {
    if (-not $blocks) {
        Write-Warning "The list of breakpoints was exhausted. The whole binary was executed. Returning."
        Stop-Process -Id $inputGenPid
        return
    }

    # Increases of the mutation rate at each iteration when in accelarated mode
    if ($env:accelerated) {
        if ($env:mutationRate -lt $MaxMutationRate) {
            $env:mutationRate += 0.001
        }
    }

    # Cleans the environment 
    if ($s) {
        Remove-PSSession $s
        $s = $null
    }
    if ($monPid) {
        Stop-Process -Id $monPid -Force
        while (Get-process -Id $monPid -ErrorAction Ignore) {}
    }

    if ($dpid) {
        Stop-Process -Id $dpid -Force -ErrorAction SilentlyContinue
        while (Get-process -Id $dpid -ErrorAction Ignore) {}
    }

    Start-Sleep -Seconds 2
    Restore-VMSnapshot -VMName $VMName -Name $CheckpointName -Confirm:$false 

    # Checks that the VM is up
    if ((Get-VM -Name $VMName).State -ne "Running") {
        Write-Error "Snapshot not in running state. Aborting."
        return
    }

    # Waits until the VM is up and running in case it starts it
    while ((Get-VM -Name $VMName).State -ne "Running" -and (Get-VM -Name $VMName).Status -ne "Operating normally") {
    } 

    # Sets the PS session for VM communication
    while (-not $s) {
        $s = New-PSSession -VMName $VMName -Credential $creds -ErrorAction SilentlyContinue
    }

    # Gets the starting time of the host and VM - used later as a reference for the collection of the event logs.
    $hostTime = Get-Date
    $timestamp = Get-date -Format "yyMMdd-HHmm"
    Write-Verbose ("Host time: " + $hostTime) 
    $vmTime = Invoke-Command -Session $s -ScriptBlock {Get-Date}

    # Connects to the debugee
    $debuggerScript = Join-Path $scriptPath "debugger.ps1"
    $hostTimeStr = $hostTime.GetDateTimeFormats('o')
    $vmTimeStr = $vmTime.GetDateTimeFormats('o')
    $dpid = (Start-Process -FilePath .\DbgShell\x64\DbgShell.exe -PassThru -ArgumentList "$debuggerScript ""$configfile"" ""$bpList"" ""$binaryNameWithoutExtension"" ""$hostTimeStr"" ""$vmTimeStr"" ").Id

    # Leaves time for the debugger to attach and starts setting breakpoints
    Write-Verbose "Waiting until the VM is ready to start interacting."
    while (-not (Test-Path $debuggerReady)) {
    }
    rm $debuggerReady

    # Waits until the VM is available for use (once the debugger lets it go after setting the breakpoints)
    while ((Get-VM -Name $VMName -ErrorAction Ignore).State -ne "Running" -or (Get-VM -Name $VMName -ErrorAction Ignore).Status -ne "Operating normally") {
    } 

    # Starts the monitoring process for that new round
    Write-Verbose "Resuming execution."
    $monitoringScriptPath = Join-Path $ScriptPath "vm-monitoring.ps1"
    $moncommand = "-configFile ""$configFile"" -hostTime ""$hostTime"" -vmTime ""$vmTime"" "
    $monPid = Start-HelperProcess -script $monitoringScriptPath -commandline $moncommand

    # Flushes the tmp folder. Tmp stores any file consumed during one VM run.
    rm "$tmp\*"

    # Consumes seed files if applicable (first run with seeds). 
    # Otherwise picks the oldest tmp file from the corpus. 
    # Loading the file in memory is not optimal space-wise but more efficient time-wise.
    if ($seeds.Count -ne 0) {
        $seedfile = $seeds[0].Fullname
        $inputbytes = Get-Content $seedfile -Encoding Byte
        $inputfilelen = $inputbytes.Length
        Write-Host $seedfile
    } else {
        do {
            $oldestTmp = ls (Join-Path $corpus "tmp*") | sort lastwritetime | select -First 1
        } while (-not $oldestTmp)
        $oldestTmpPath = $oldestTmp.Fullname
        $inputbytes = Get-Content $oldestTmp -Encoding Byte
        $inputfilelen = $inputbytes.Length
        Write-Host $oldestTmpPath
    }

    # Makes sure the pool is full for future consumption
    $inputGenPid = Start-HelperProcess -script $inputGeneratorPath -commandline $inputcommand

    # If the virtual disk type option is passed, several virtual disks will be mounted for each file
    if ($VirtualDiskType) {      
        # 5 mutated files are selected, the template is added, as well as $null (no file)
        # as there is no cmdlet to remove a floppy disk, the first run will be on no disk, then on the template, the other ones will just replace it. 
        if ($VirtualDiskType.GetType().Name -eq "String") {
            do {
                [System.Collections.ArrayList]$fs = ls (Join-Path $fscorpus "tmp*$VirtualDiskType") | sort lastwritetime | select -First 5
            } while ($fs.Count -ne 5)
            $fs.Insert(0, $fsTemplate)
            $fs.Insert(0, $null) 
            # Regenerates files for the pool now some have been consumed.
            $fsGenPid = Start-HelperProcess -script $fsGeneratorPath -commandline $fscommand
        } 
        # case of several file types
        else {
            do {
                [System.Collections.ArrayList]$fs = ls (Join-Path $fscorpus "tmp*") | sort lastwritetime | select -First 5
            } while ($fs.Count -ne 5)
            foreach ($template in $fsTemplate) {
                $fs.Insert(0, $template)
            }
            $fs.Insert(0, $null)
            foreach ($fscommand in $fscommands) {
                $fsGenPid = Start-HelperProcess -script $fsGeneratorPath -commandline $fscommand
            }
        } 
    } 

    # Pre-creates a timestamp for the corpus
    $ctimestamp = Get-date -Format "yyMMdd-HHmmss" 
    # Keeps the largest index of change on a file for the corpus (useful with virtual disks as one input file runs several times) 
    $largestKeepIndex = 0

    # Executes the payload on the VM. One iteration per virtual disk attached, only 1 if not fuzzing virtual disks.
    :loop do {
        
        # Input file offset
        $offset = 0

        # Sets an index in case the current file increases coverage. That index is the highest offset that triggered an increase. 
        $keepIndex = New-Object System.Collections.ArrayList

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
                    # TODO: find a way to update the disk
                    Set-VMHardDiskDriveForFuzzing -VMName $VMName -Path $fsfile -s $s
                    # Set-VMHardDiskDrive -VMName $VMName -Path $fsfile
                } else {
                    Write-Warning "`tDid not recognize the format of $fsfile."
                }
            } else { # case of multiple fuzzed formats
                if ($VirtualDiskType.Contains("vfd") -and (($fsfile -eq $null) -or ([io.path]::GetExtension($fsfile) -eq ".vfd"))) {
                    Set-VMFloppyDiskDrive -VMName $VMName -Path $fsfile
                } 
                if ($VirtualDiskType.Contains("iso") -and (($fsfile -eq $null) -or ([io.path]::GetExtension($fsfile) -eq ".iso"))) {
                    Set-VMDvdDrive -VMName $VMName -Path "$fsfile"  
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
            }

            # Exclusion list lists
            if (($ioport -eq 0x64) -and ($action -eq 1) -and ($value -ge 0xF0)) {
                Write-Debug "W $x_ioport $numbytes $x_value - Skipping, resuming at index $offset" 
                continue
            }
            if (($ioport -eq 0x92) -and ($action -eq 1) -and (($value -band 1) -eq 1)) {
                Write-Debug "W $x_ioport $numbytes $x_value - Skipping, resuming at index $offset" 
                continue
            }
            # A20 gate & PS2 system reset
            if (($ioport -eq 0x64) -and ($action -eq 1) -and ($value -eq 0xd1)) {
                $ps2Command = $true
            }
            if ($ps2Command -and ($ioport -eq 0x60) -and ($action -eq 1) -and (($value -band 1) -eq 1) -and (($value -band 2) -eq 0)) {
                Write-Debug "W $x_ioport $numbytes $x_value - Skipping, resuming at index $offset" 
                continue
            }
            if ($ps2Command -and ($ioport -eq 0x60) -and ($action -eq 1) -and (($value -band 1) -eq 0)) {
                Write-Debug "W $x_ioport $numbytes $x_value - Skipping, resuming at index $offset" 
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
        
            try {
                Invoke-Command -Session $s -ScriptBlock {param($command) iex -command $command} -ArgumentList @($command) -ErrorAction Stop | Out-Null
            } catch {
                if ($_.Exception -like "No valid session were specified*" -or $_.Exception -like "*The session state is Broken*") {
                    Write-Host "An error occured. On hold. Error message: $_". -ForegroundColor Red
                    "" > $hold
                    break loop
                }
            }
                
            $newBlockList = Get-Content $bpList
            if ($newBlockList.Count -ne $blocks.Count) {
                $keepIndex.Add($offset) > $null
                $blocks = $newBlockList
            }    
        } 

        # Adds to the corpus when the coverage was updated by the debugger during that run - only if not consuming the seed.
        if (($keepIndex.count -ne 0) -and ($seeds.Count -eq 0)) {
            # File system corpus
            if ($VirtualDiskType -and $fsfile -and ($fsfile -notlike "*\template.*")) {
                $fsindex = $fs.IndexOf($fsfile)
                $extension = [io.path]::GetExtension($fsfile)
                $newFsResident = Join-Path $fsCorpus ("corpus-$ctimestamp-$fsindex" + $extension)
                Copy-Item $fsfile $newFsResident
            }    
            # IO input file in accelarated mode, any new increase triggers a new file
            if ($env:accelerated) {
                foreach ($k in $keepIndex) { 
                    if ($k -gt $largestKeepIndex) {
                        $largestKeepIndex = $k
                        $newResident = Join-Path $corpus "corpus-$ctimestamp-$k"
                        $fileStream = [System.IO.File]::OpenWrite($newResident)
                        $fileStream.Write($inputbytes, 0, $k)
                        $fileStream.Close()
                    }
                }
            } else {
                # Cuts at the latest change
                if ($keepIndex[-1] -gt $largestKeepIndex) {
                    $largestKeepIndex = $keepIndex[-1]
                    $newResident = Join-Path $corpus "corpus-$ctimestamp"
                    $fileStream = [System.IO.File]::OpenWrite($newResident)
                    $fileStream.Write($inputbytes, 0, $keepIndex[-1])
                    $fileStream.Close()
                }
            }
            $idleloopCount = 0
        } else {
            # If the coverage was not updated, increases a counter used to switch in accelerated mode
            $idleloopCount += 1
        }
                
        # If fuzzing the file system, sets the file system accordingly
        if ($VirtualDiskType) {
            $fs.Remove($fsfile)
            if ($fsfile) {
                if ([io.path]::GetExtension($fsfile) -eq ".vfd") {
                    Set-VMFloppyDiskDrive -VMName $VMName -Path $null
                } elseif ([io.path]::GetExtension($fsfile) -eq ".iso") {
                    Set-VMDvdDrive -VMName $VMName -Path $null
                } elseif ([io.path]::GetExtension($fsfile) -eq ".vhd") {
                    # Remove-VMHardDiskDrive -VMName $VMName -Path $fsfile
                    Unset-VMHardDiskDriveForFuzzing -VMName $VMName -Path $fsfile -s $s
                }else {
                    # TODO
                }
                if ($fsfile -notlike "*\template.*") {
                    Move-Item $fsfile $tmp
                }
            }
        }
    } while ($fs.Count -ne 0)

    # Handles the case of a crash
    if (Test-Path (Join-Path $PSScriptRoot "on-hold")) {
        while (Test-Path (Join-Path $PSScriptRoot "on-hold")) {
            Start-Sleep -Seconds 10
        }
        $monPid = $null
        Write-Host "Resuming execution with a new case."
    }

    # Updates the seed list if running against the seeds.
    if ($seeds.Count -ne 0) {
        $seeds.Remove($seeds[0])
    } else {
        Move-Item $oldestTmpPath $tmp
    }

    # Switches to accelerated mode after 100 consecutive runs that did not increase the coverage
    if ((-not $env:accelerated) -and ($idleloopCount -ge 100)) {
        Write-Host "Entering stage 2 - accelarated fuzzing" -ForegroundColor Magenta
        $env:accelerated = $true
    }
}
