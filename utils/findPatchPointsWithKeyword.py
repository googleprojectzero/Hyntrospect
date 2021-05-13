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

import idautils
import idaapi
import ida_nalt
import idc

if len(idc.ARGV) != 2:
	print("Need to have the output filepath as an argument. Using default: ~\Desktop\patches.txt")
	from os.path import expanduser
	home = expanduser("~")
	filepath = home + "\\Desktop\\patches.txt"
else:
	filepath = idc.ARGV[1]
print(filepath)

auto_wait()

patchpoints = set()
base = idaapi.get_imagebase()

keyword = "@Ide"

for seg_ea in idautils.Segments():
    name = idc.get_segm_name(seg_ea)
    if name != ".text":
        continue

    start = idc.get_segm_start(seg_ea)
    end = idc.get_segm_end(seg_ea)
    for func_ea in idautils.Functions(start, end):
        funcName = idc.get_func_name(func_ea)
        # Check if the function name starts with "Player_GetStats"
        if keyword in funcName:
            print(funcName)
            f = idaapi.get_func(func_ea)
            if not f:
                continue
            for block in idaapi.FlowChart(f):
                if f.start_ea <= block.start_ea < f.end_ea:
                    patchpoints.add(block.start_ea - base)

with open(filepath, "w") as f:
    f.write('\n'.join(map(hex, sorted(patchpoints))))

print("Done, found {} patchpoints".format(len(patchpoints)))
