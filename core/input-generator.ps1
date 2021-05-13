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
    [Parameter(Mandatory=$true)][int]$maxInputSize,
    [Parameter(Mandatory=$true)][int]$minInputSize
)

$helper = Join-Path $PSScriptRoot helper.psm1
Import-Module $helper -Force

$corpus = Join-Path $HostOutputDir "corpus"

# Initialization of the corpus
if (-not (Test-Path $corpus -PathType Container)) {
    mkdir $corpus | Out-Null
}

$seed = ls $corpus | Where {($_.Name -like "corpus*") -or ($_.Name -like "seed*")  -or ($_.Name -like "template*")} 
if ($seed -eq $null) {
    Init-Corpus -corpus $corpus
}

$availableFiles = Join-Path $corpus "tmp*"
while ((-not (ls $availableFiles)) -or ((ls $availableFiles | measure).Count -lt 10)) {
    $switch = Get-Random -Minimum 0 -Maximum 9
    # 10%: random file generation, 30%: corpus file appended, 60%: mutated corpus file
    switch($switch) {
        0 {
            $tmp = "tmp_" + (Get-Date -Format "yyMMdd-HHmmss") + "_random"
            $filepath = Join-Path $corpus $tmp
            New-RandomFile -filepath $filepath -minInputSize $minInputSize -maxInputSize $maxInputSize
        }
        1 {New-AppendedFile -corpus $corpus -maxInputSize $maxInputSize}
        2 {New-AppendedFile -corpus $corpus -maxInputSize $maxInputSize}
        3 {New-AppendedFile -corpus $corpus -maxInputSize $maxInputSize}
        4 {New-MutatedFile -corpus $corpus}
        5 {New-MutatedFile -corpus $corpus}
        6 {New-MutatedFile -corpus $corpus}
        7 {New-MutatedFile -corpus $corpus}
        8 {New-MutatedFile -corpus $corpus}
        9 {New-MutatedFile -corpus $corpus}
    }
}