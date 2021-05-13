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
    [Parameter(Mandatory=$true)][string]$InitialBpList,
    [Parameter(Mandatory=$true)][string]$UpdatedBpList,
    [Parameter(Mandatory=$true)][string]$OutputDir,
    [Parameter(Mandatory=$true)][string]$Binary
)

$iBp = Get-Content $InitialBpList
$uBp = Get-Content $UpdatedBpList
$oFile = Join-Path $OutputDir ("coverage-" + (Split-Path $UpdatedBpList -Leaf))
$binaryRoot = [io.path]::GetFileNameWithoutExtension($Binary)

foreach ($block in $iBp) {
    if (-not ($uBp.Contains($block))) {
        $text = $binaryRoot + "+" + $block 
        Add-Content -Path $oFile -Value $text  
    }
}
