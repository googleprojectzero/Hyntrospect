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
    [Parameter(Mandatory=$true)][string]$HostOutputDir, 
    [Parameter(Mandatory=$true)][string]$VirtualDiskType
)

$helper = Join-Path $PSScriptRoot helper.psm1
Import-Module $helper -Force

$corpus = Join-Path $HostOutputDir "fscorpus"

# at least the template is in the test file

$availableFiles = Join-Path $corpus "tmp*$VirtualDiskType"
while ((-not (ls $availableFiles)) -or ((ls $availableFiles | measure).Count -lt 10)) {
    # TODO: over time, may update the strategy to switch over other functions that do more targetted operations on the file system
    # Picks a random wait in case there are several file formats (to let them intertwine)
    Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 100)
    New-MutatedFile -corpus $corpus -mutRate 0.3 -extension $VirtualDiskType
}