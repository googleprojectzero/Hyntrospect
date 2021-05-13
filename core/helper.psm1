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


# IO COMMAND
function Set-IoCommand ($VMChipsecFilepath, $port, $len, $value) {
    if ($value -ne $null) {
        $command = "py.exe $VMChipsecFilepath io 0x" + [Convert]::ToString($port, 16) + " " + $len + " 0x" + [Convert]::ToString($value, 16)
    } 
    else {
        $command = "py.exe $VMChipsecFilepath io 0x" + [Convert]::ToString($port, 16) + " " + $len
    }
    return $command
}

# INPUT GENERATION AND CONSUMPTION
function Init-Corpus ($corpus) {
    New-RandomFile -filepath (Join-Path $corpus "corpus-seed") -minInputSize 200 -maxInputSize 300
}

function New-RandomFile ($filepath, $minInputSize, $maxInputSize) {
    $bufferSize = Get-Random -Minimum $minInputSize -Maximum $maxInputSize
    $buffer = [System.Byte[]]::new($bufferSize)
    
    $random = [System.Random]::new()
    $random.NextBytes($buffer)

    $fileStream = [System.IO.File]::OpenWrite($filePath)
    $fileStream.Write($buffer, 0, $buffer.Length)
    $fileStream.Close()
}

# This function enables to pick corpus files given a weight: 1 for the oldest, 2 for the second oldest, ... 
# The most recent successful path opening files are more likely to be chosen.
function Select-BaseFile ($corpus, $extension) {
    if ($extension) {
        $residents = ls $corpus | Where {($_.Name -like "corpus*$extension") -or ($_.Name -like "seed*$extension")  -or ($_.Name -like "template*$extension")} | Sort-Object -Property LastWriteTime 
    } else {
        $residents = ls $corpus | Where {($_.Name -like "corpus*") -or ($_.Name -like "seed*")  -or ($_.Name -like "template*")} | Sort-Object -Property LastWriteTime 
    }
    $n = ($residents | measure).Count

    # in the second phase of the fuzzer run, weights the files
    if ($env:accelarated) {
        # Maths: sum(1..n) = n * (n + 1) / 2 
        $totalweight = $n * ($n+1) / 2
        $value = (Get-Random -Minimum 0 -Maximum $totalweight) + 1
        # Value to index
        $index = 0
        for ($i = 1; $i -le $n; $i++) {
            if ($value -le ($i * ($i+1) /2 )) {
                continue;
            }
            $index += 1
        }
    } else {
        $index = Get-Random -Minimum 0 -Maximum $n 
    }
    $target = ($residents[$index]).FullName
    return $target
}

# Function that flips bits. It uses a global mutationRate that increases over runs.
function New-MutatedFile ($corpus, $mutRate = $env:mutationRate, $extension) {
    $target = Select-BaseFile -corpus $corpus -extension $extension

    $tmp = "tmp_" + (Get-Date -Format "yyMMdd-HHmmss") + "_mut_" + [io.path]::GetFileNameWithoutExtension($target)
    if ($extension) {
        $tmp += ".$extension"
    }
    $filepath = Join-Path $corpus $tmp

    # Number of bits that can be flipped
    $bitslen = (ls $target).Length * 8
    # if ($bitslen -eq 0) {
    #     $bitslen = 8
    # }
    $maxMutations = ((1, [int]([float]$env:mutRate * $bitslen)) | Measure-Object -Maximum).Maximum
    $numMutations = [int](Get-Random -Minimum 1 -Maximum ($maxMutations+1))

    # Loads the file in memory to prepare the mutated image in memory before rewriting to disk the modified version
    $bytes = [System.IO.File]::ReadAllBytes($target)

    # That algorithm is problematic for high mutation rates: finding a non mutated index randomly is no longer efficient and the list of indexes grows.
    $i = 0
    $mutatedIndexes = @() 
    while ($i -lt $numMutations) {
        do {
            $bitnumber = Get-Random -Minimum 0 -Maximum $bitslen
        } while ($mutatedIndexes.Contains($bitnumber))
        $byteIndex = [math]::floor($bitnumber / 8)
        $bitIndex = $bitnumber % 8
        $value = 1 -shl $bitindex
        $bytes[$byteIndex] = $bytes[$byteIndex] -bxor $value
        $mutatedIndexes += $bitnumber 
        $i += 1
    }

    [System.IO.File]::WriteAllBytes($filepath, $bytes)
}

# Function that prepends random bytes to one of the corpus files
function New-AppendedFile ($corpus, $maxInputSize) {
    $target = Select-BaseFile -corpus $corpus

    $tmp = "tmp_" + (Get-Date -Format "yyMMdd-HHmmss") + "_app_" + [io.path]::GetFileNameWithoutExtension($target)
    $filepath = Join-Path $corpus $tmp

    $bytes = Get-Content $target -Encoding Byte
    if ((ls $target).Length -ge $maxInputSize) {
        # if the maximum length is already reached, adds ar arbitrary value of 30 bytes
        $maxAddedBytes = 30
    } else {
        $maxAddedBytes = $maxInputSize - ((ls $target).Length)
    }
    $bufferSize = Get-Random -Minimum 0 -Maximum $maxAddedBytes
    $buffer = [System.Byte[]]::new($bufferSize)
    $random = [System.Random]::new()
    $random.NextBytes($buffer)

    $finalbuff = [System.Byte[]]::new($bufferSize + ($bytes.Count))
    for ($i = 0; $i -lt $bytes.Count; ++$i)
    {
        $finalbuff[$i] = $bytes[$i];
    }
    for ($i = 0; $i -lt $buffer.Count; ++$i)
    {
        $finalbuff[$bytes.Count + $i] = $buffer[$i];
    }

    $fileStream = [System.IO.File]::OpenWrite($filePath)
    $fileStream.Write($finalbuff, 0, $finalbuff.Count)
    $fileStream.Close()
}

function Consume-Bytes ($bytes, $offset, $numBytes, $filelen) {
    if (($offset + $numBytes) -le $filelen) {
        if ($numBytes -eq 1) {
            $value = $bytes.GetValue($offset)
        }
        elseif ($numBytes -eq 2) {
            $value = [bitconverter]::ToUInt16($bytes, $offset)
        }
        elseif ($numBytes -eq 4) {
            $value = [bitconverter]::ToUInt32($bytes, $offset)
        }
        else {
            $value = 0
        }
    } else {
        $value = 0
    }
    $offset += $numBytes
    return $offset, $value
}

# BREAKPOINTS HANDLING
function Init-BreakpointList ($ida, $idb, $bpscript, $bpList, $binary) {
    # Courtesy to Samuel Gross (saelo)
    $p = Start-Process -FilePath $ida -ArgumentList "-A -o""$idb"" -S""$bpscript $bpList"" $binary" -PassThru -WindowStyle Hidden
    while (-not (Test-Path $bpList) -or ((ls $bpList).Length -eq 0)) {
    }
    Stop-process $p.Id
    Start-Sleep -Seconds 1
    $idbDir = [io.Path]::GetDirectoryName($idb)
    rm $idbDir\*.til
    rm $idbDir\*.id*
    rm $idbDir\*.nam
}

# VM SANITY CHECKS 
# Check-VMSanity is no longer used as it is too slow and misses some quick VM state changes.
function Check-VMSanity ($VMName) {
    Try {
        $vm = Get-VM -Name $VMName -ErrorAction Stop
    } 
    Catch { 
        # This means the VM is hanging (while the breakpoints have already been set)
        return $false
    }
    $state = $vm.State
    $status = $vm.Status
    if ($state -ne "Running") {
        Write-Error "VM not running. State: $state, status: $status."
        return $false
    }
    return $true
}

# CRASH HANDLING
function Get-VMKernelCrashDump ($VMName, $creds, $CrashDir, $startTime) {
    $newPath = Join-Path $CrashDir "Memory.dmp"

    $testDate = Invoke-Command -VMName $VMName -ScriptBlock {param($startTime) if (Test-Path $env:SystemRoot\Memory.dmp) {(Get-Item $env:SystemRoot\Memory.dmp | Select -ExpandProperty LastWriteTime) -gt ($startTime)}} -Credential $creds -ArgumentList $startTime
    if($testDate) {
        [Byte[]]$bytes = Invoke-Command -VMName $VMName -ScriptBlock {Get-Content $env:SystemRoot\Memory.dmp -encoding Byte} -Credential $creds
        Set-Content -Value $bytes -Path $newPath -Encoding Byte
    }
}

function Get-HostEventLogs ([string]$crashDir, [DateTime]$startTime) {
    $channels = @("Microsoft-Windows-Hyper-V-Hypervisor-Admin", "Microsoft-Windows-Hyper-V-Hypervisor-Analytic", "Microsoft-Windows-Hyper-V-Hypervisor-Operational", "Microsoft-Windows-Hyper-V-Worker-Admin","Microsoft-Windows-Hyper-V-Worker-Analytic", "Microsoft-Windows-Hyper-V-Worker-Operational")

    $timediff = [int64](((Get-Date) - $startTime).TotalMilliseconds)
  
    foreach ($channel in $channels) {
        $evtxFile = Join-Path $CrashDir "host-$channel.evtx"

        # Level=1: critical, Level=2: error, Level=3: warning
        $query = '*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime)<=' + $timediff + ']]]'

        wevtutil epl $channel $evtxFile "/q:$query" /ow:true
    }
}

function Get-GuestEventLogs ($VMName, $creds, $CrashDir, $startTime) {
    $logfile = Join-Path $CrashDir "guest-System.txt"
    $logs = Invoke-Command -VMName $VMName -ScriptBlock {param($startTime) Get-EventLog -LogName "System" -After $startTime | Where EntryType -in @("Critical", "Error", "Warning", "0") | Select-Object -Property *} -Credential $creds -ArgumentList $startTime
    $logs | Out-File $logfile 
}

function Collect-CrashInfo ($VMName, $creds, $crashDir, $hostTime, $vmTime, $err) {
    # If this comes from the monitoring process, gets the latest error
    if ($err) {
        Add-Content -Value $err -Path (Join-Path $crashDir "error.txt")
        Add-Content -Value $err.ScriptStackTrace -Path (Join-Path $crashDir "error.txt")
        Add-Content -Value $err.InvocationInfo -Path (Join-Path $crashDir "error.txt")
    }
    
    # Collects the hosts logs.
    Write-Host("Collecting the logs on the host")
    Get-HostEventLogs -startTime $hostTime -CrashDir $crashDir

    # Reboots the VM, calculates its initial time, and collects its data
    # If both the monitoring process and the debugger are operating, this section will only the executed by the debugger once it receives user input.
    while ((Get-Content $hold) -eq "Debugger process handling a crash.") { }  

    Write-Host("Rebooting the VM.")
    Restart-VM -Name $VMName -Confirm:$false -Force
    while (((Get-VM -Name $VMName).state -ne "Running") -or -not (Invoke-Command -VMName $VMName -ScriptBlock {return $true} -Credential $creds -ErrorAction SilentlyContinue)) {
        Start-Sleep -Seconds 5
    }
    Write-Host("Extracting the logs.")
    Get-VMKernelCrashDump -VMName $VMName -creds $creds -CrashDir $crashDir -startTime $vmTime
    Get-GuestEventLogs -VMName $VMName -creds $creds -CrashDir $crashDir -startTime $vmTime

}

function New-CrashReport ($ConfigFile, $tmp, [switch]$mini) {
    $config = Get-Content -Path $ConfigFile | ConvertFrom-Json
    $HostOutputDir = $config.HostOutputDir
    $VirtualDiskType = $config.VirtualDiskType

    $corpus = Join-Path $HostOutputDir "corpus"

    if (-not $tmp) {
        $tmp = Join-Path $HostOutputDir "tmp"
    }

    $crashTime = Get-Date -Format "yy-MM-dd_HH-mm"
    if ($mini) {
        $crashDir = New-Item -Path $HostOutputDir -Name ("Crash_debugger_" + $crashTime) -ItemType Container -Force
    } else {
        $crashDir = New-Item -Path $HostOutputDir -Name ("Crash_monitoring_" + $crashTime) -ItemType Container -Force
    }

    $inputfile = ls (Join-Path $corpus "tmp*") | sort lastwritetime | select -First 1
    Copy-Item $inputfile -Destination $crashDir

    Copy-Item $ConfigFile -Destination $crashDir

    if ($VirtualDiskType) {
        $fscorpus = Join-Path $HostOutputDir "fscorpus"
        if ($VirtualDiskType.GetType().Name -eq "String") {
            $fsTemplate = Join-Path $fscorpus "template.$VirtualDiskType"
            Copy-Item $fstemplate -Destination $crashDir
        } else {
            foreach ($format in $VirtualDiskType) {
                $fsTemplate = Join-Path $fsCorpus "template.$format"
                Copy-Item $fstemplate -Destination $crashDir           
            }
        }
        $lastFsfile = ls (Join-Path $fscorpus "tmp*") | sort lastwritetime | select -First 1    
        Copy-Item $lastFsfile -Destination $crashDir
    }

    # Copy of all files related to this VM runtime
    Copy-Item "$tmp\*" -Destination $crashDir

    return $crashDir
}

# Steps to resume normal execution
function RecoverFrom-Crash {
    Write-Host "Crash handling done. Resuming execution."
    # Signals the fuzzer main that it can continue. On-hold is created by the fuzzer main when the PowerShell direct session stops responding.
    $hold = Join-Path $PSScriptRoot "on-hold"
    if (Test-Path -Path $hold) {
        Remove-Item $hold
        
    }

}

# START A HELPER PROCESS
function Start-HelperProcess ($script, $commandline) {
    $commandline = "&'$script' " + $commandline
    $b64 = [convert]::ToBase64String([System.Text.encoding]::Unicode.GetBytes($commandline))
    $process = Start-Process powershell -WindowStyle hidden -PassThru -ArgumentList '-EncodedCommand',`"$b64`"  
    return $process.Id
}

# VHD HANDLING
function Set-VMHardDiskDriveForFuzzing ($VMName, $Path, $s) {
    if ($Path) {
        $VMFolder = "C:\tmp"
        $vhdFileName = [System.IO.Path]::GetFileName($Path)
        $VMDestinationPath = Join-Path $VMFolder $vhdFileName    
        Copy-VMFile $VMName -SourcePath $Path -DestinationPath $VMDestinationPath -CreateFullPath -FileSource Host -Force
        Invoke-Command -Session $s -ScriptBlock {param($VMDestinationPath) Mount-DiskImage –ImagePath $VMDestinationPath | Out-Null} -ArgumentList @($VMDestinationPath)
    }
}

function Unset-VMHardDiskDriveForFuzzing ($VMName, $Path, $s) {
    if ($Path) {
        $VMFolder = "C:\tmp"
        $vhdFileName = [System.IO.Path]::GetFileName($Path)
        $VMDestinationPath = Join-Path $VMFolder $vhdFileName 
        Invoke-Command -Session $s -ScriptBlock {param($VMDestinationPath) Dismount-DiskImage –ImagePath $VMDestinationPath | Out-Null; rm $VMDestinationPath} -ArgumentList @($VMDestinationPath)
    }
}