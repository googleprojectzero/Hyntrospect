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

param (
    [Parameter(Mandatory = $false, ParameterSetName = 'FuzzerMode')][string]$configFile,
    [Parameter(Mandatory = $true, ParameterSetName = 'ReproCase')][string]$reproFolder
)

# Validating config file / repro folder and its config file - only the arguments requiring an authentication on the VM will be checked later
if ($reproFolder) {
    if (-not (Test-Path $reproFolder -PathType Container)) {
        Write-Error "Repro folder path given but it is not a valid folder path. Aborting."
        return
    }
    $configFile = Join-Path $reproFolder "config.json"
    $configFile = Resolve-Path $configFile
    if (-not (Test-Path $configFile)) {
        Write-Error "The repro folder needs to contain a configuration file entitled 'config.json'. Aborting."
        return
    }
} else {
    if ($configFile) {
	    if (-not (Test-Path $configFile)) {
            Write-Error "Config file path given but it is not a valid path. Aborting."
            return
        }
	    $configFile = Resolve-Path $configFile
    } else {
	    if (-not (Test-Path ".\config.json")) {
            Write-Error "Config file path not given, config.json not found next to Main.ps1. Aborting."
            return
        }
	    $configFile = Resolve-Path ".\config.json"
    }
}

$config = Get-Content -Path $configFile | ConvertFrom-Json
$VMName = $config.VMName
$VMUsername = $config.VMUsername
$VMPassword = $config.VMPassword
$CheckpointName = $config.VMCheckpointName
$HostOutputDir = $config.HostOutputDir
$VMChipsecFilepath = $config.VMChipsecFilepath
$MaxInputSize = $config.MaxInputSize
$MinInputSize = $config.MinInputSize
$MaxMutationRate = $config.MaxMutationRate  
$Target = $config.Target
$IOPortRead = $config.IOPortRead
$IOPortWrite = $config.IOPortWrite
$IdaPath = $config.HostIdaPath
$VirtualDiskType = $config.VirtualDiskType

if ($VirtualDiskType) {
    if ($VirtualDiskType.GetType().Name -ne "String" -and $VirtualDiskType.GetType().Name -ne "Object[]"){
        Write-Error "VirtualDiskType is optional. If given, legit and fuzzed file systems will be mounted in the VM. The supported values for this parameter are either vfd, vhd vhdx or iso, or an array containing several of those values. Illegal format. Aborting."
        return
    }
    if (($VirtualDiskType.GetType().Name -eq "String") -and -not (($VirtualDiskType -eq "vfd") -or ($VirtualDiskType -eq "vhd") -or ($VirtualDiskType -eq "vhdx") -or ($VirtualDiskType -eq "iso"))) {
        Write-Error "VirtualDiskType is optional. If given, legit and fuzzed file systems will be mounted in the VM. The supported values for this parameter are either vfd, vhd, vhdx, or iso, or an array containing several of those values. The given string is not a legit value. Aborting."
        return
    } elseif ($VirtualDiskType.GetType().Name -eq "Object[]") {
        foreach ($vdisk in $VirtualDiskType) {
            if (($vdisk -ne "vfd") -and ($vdisk -ne "vhd") -and ($vdisk -ne "vhdx") -and ($vdisk -ne "iso")) {
                Write-Error "VirtualDiskType is optional. If given, legit and fuzzed file systems will be mounted in the VM. The supported values for this parameter are either vfd, vhd, vhdx or iso, or an array containing several of those values. The given array does not contain legit values. Aborting."
                return
            }
        } 
    } else {}
}

if ($reproFolder) {
    $reproFile = ls $reproFolder | Where -Property Name -like tmp* | Where -Property Name -NotLike *.*
    if (-not $reproFile -or $reproFile.Count -gt 1) {
        Write-Error "No reproduction file found in the repro folder, or there are several instead. There should be 1 repro file that starts with tmp and be the only tmp file without extension. Aborting."
        return
    }
    $reproFile = $reproFile.FullName

    if ($VirtualDiskType) {
        $vd = New-Object System.Collections.ArrayList
        if ($VirtualDiskType.GetType().Name -eq "String") {
            $vdfiles = Join-Path $reproFolder "*.$VirtualDiskType"
            foreach ($f in (ls $vdfiles | Sort LastWriteTime)) {
                $vd.Add((Resolve-Path $f).Path) > $null
            }
        } else {
            $lsvdfiles = $null
            foreach ($format in $VirtualDiskType) {
                $vdfiles = Join-Path $reproFolder "*.$format"
                $lsvdfiles += [System.IO.FileSystemInfo[]] (ls $vdfiles)
            }
            $lsvdfiles = $lsvdfiles | Sort LastWriteTime
            foreach ($f in ($lsvdfiles)) { 
                $vd.Add((Resolve-Path $f).Path) > $null
            } 
        }
    }
    if (-not $Verbose) {
        Write-Warning "For more details on the commands run on the guest, rerun this command with -Verbose. Disabled by default to speed up the run."
    }
}

Push-Location
cd "$PSScriptRoot\core"

if (-not (Test-Path ".\DbgShell\x64\DbgShell.exe")) {
    Write-Error "DbgShell folder cannot be found. Expecting to find .\DbgShell\x64\DbgShell.exe in core. Aborting."
    Pop-Location
    return
}
if (-not (Test-Path ".\fuzzer-master.ps1")) {
    Write-Error "PS2 fuzzer master not found. Expecting to find fuzzer-master.ps1 in core. Aborting."
    Pop-Location
    return    
}
if (-not (Test-Path ".\replay-case.ps1")) {
    Write-Error "PS2 replay case script not found. Expecting to find replay-case.ps1 in core. Aborting."
    Pop-Location
    return    
}
if (-not (Test-Path "..\config.json")) {
    Write-Error "Config file not found. Expecting to find config.json next in the same folder as Main.ps1. Aborting."
    Pop-Location
    return 
}

# Turning local paths to full paths (needed within DbgShell)
$ps2 = Resolve-Path ".\fuzzer-master.ps1"
$replay = Resolve-Path ".\replay-case.ps1"


if (($VMName -eq $null) -or ($VMUsername -eq $null) -or ($VMPassword -eq $null) -or ($CheckpointName -eq $null) -or ($HostOutputDir -eq $null) -or ($VMChipsecFilepath -eq $null) -or ($MaxInputSize -eq $null) -or ($MinInputSize -eq $null) -or ($Target -eq $null) -or ($IOPortRead -eq $null) -or ($IOPortWrite -eq $null)) {
    Write-Error "The config file must at least contain the fields: 'VMName', 'VMCheckpointName', 'VMUsername', 'VMPassword', 'HostOutputDir', 'VMChipsecFilepath', 'MaxInputSize', 'MinInputSize', 'Target', 'IOPortRead', 'IOPortWrite'. Aborting."
    Pop-Location
    return
}
if ((Test-Path $HostOutputDir) -ne $true -or (Test-Path $HostOutputDir -PathType Container) -eq $false) {
    Write-Error "Invalid output directory. Please provide an existing directory. Aborting."
    Pop-Location
    return
}
$Error.Clear()
Get-VM -Name $VMName -ErrorAction SilentlyContinue | Out-Null
if ($Error.Count -ne 0) {
    Write-Error "The VM Name is invalid or this PowerShell session is not elevated. Aborting."
    Pop-Location
    return
}
if ((Get-VMSnapshot -VMName $VMName | Where Name -eq $CheckpointName) -eq $null) {
    Write-Error "The VM Checkpoint name is invalid. Aborting."
    Pop-Location
    return
}

#Test the credentials 
$secpass = ConvertTo-SecureString -String $VMPassword -AsPlainText -Force
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($VMUsername, $secpass)
Try {
    Invoke-Command -VMName $VMName -Credential $creds -ScriptBlock {"Test creds" > $null} -ErrorAction Stop
} 
Catch { 
    Write-Error "The username or password is incorrect for VM $VMName, or the VM is not up and ready to run commands. Returning."
    Pop-Location
    return 
}

if (($MaxInputSize -le 0) -or ($MaxInputSize -gt 100000)) {   
    Write-Error "MaxInputSize must be positive and below 100000. Aborting."
    Pop-Location
    return
}

if (($MinInputSize -le 0) -or ($MinInputSize -ge $MaxInputSize)) {   
    Write-Error "MinInputSize must be positive and below MaxInputSize. Aborting."
    Pop-Location
    return
}

if (-not (Test-Path $Target -PathType Leaf)) {
    Write-Error "Target is not a valid path. Aborting."
    Pop-Location
    return
}

if ($IdaPath -and -not (Test-Path $IdaPath -PathType Leaf)) {
    Write-Error "HostIdaPath given but it is invalid. HostIdaPath should be the fullpath of ida64.exe or ida.exe. Aborting."
    Pop-Location
    return
}

if ($MaxMutationRate -and (($MaxMutationRate -gt 1) -or ($MaxMutationRate -le 0))) {
    Write-Error "MaxMutationRate is optional. If given, it should be > 0 and <= 1. Default value: 0.3."
    Pop-Location
    return
}

# Starting DbgShell with the payload.
if ($reproFolder) {
    if ($VirtualDiskType) {
        Write-Host "Replaying $reproFile with replay-case parametered through config.json, with the following disks: $vd."
        &$replay -configFile $configFile -reproFile $reproFile -folder $reproFolder -virtualdisks $vd           
    } else {
        Write-Host "Replaying $reproFile with replay-case parametered through config.json."
        &$replay -configFile $configFile -reproFile $reproFile -folder $reproFolder
    }
} else {
    Write-Host "Starting DbgShell with fuzzer-master parametered through config.json."
    &$ps2 -configFile $configFile
}

Pop-Location