#! /usr/bin/env python3
import subprocess
import fileinput
import sys
import re
import os

if len(sys.argv) < 2:
    print("Executable file is missing")
    print("Usage: python measure_heap_consumers.py executable_file")
    quit()

demo_application = sys.argv[1]

process = subprocess.Popen("export MALLOC_TRACE=./heap_consumers.txt; " + demo_application,
                           shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
process.wait()

print("Executing " + os.path.basename(demo_application) + " application...")
if process.returncode == 0:
    print("Application executed successfully.")
else:
    print("Failed to successfully execute application.")
    quit()

print("Collecting results...")

top_heap_memory_allocations = {}

for line in fileinput.input("heap_consumers.txt", inplace=True):
    # find address in memory map
    start = line.find('[')
    end = line.find(']')

    if start != -1 and end != -1 and line.find(demo_application) != -1 and line.find('+') != -1:
        address = line[start + 1:end]
        # get line in source code for address in memory map
        process = subprocess.Popen("addr2line -e " + demo_application + " " + address,
                                   shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        process.wait()
        # replace address with line number
        addr2line = process.stdout.readline().decode("utf-8").rstrip()
        line = line.replace(address, addr2line).rstrip()
        # update line in a file with line number instead of an address
        print(line)
        # get size of memory allocation
        size_of_allocation = int(line[[m.start() for m in re.finditer(r"0x", line)][1] + 2: len(line)], 16)
        # update dictionary
        top_heap_memory_allocations[size_of_allocation] = top_heap_memory_allocations.get(size_of_allocation, 0) + 1

print("Results for heap memory allocation are collected.\n")

top_heap_memory_allocations = sorted(top_heap_memory_allocations.items(), key=lambda x: x[1], reverse=True)
print("{:<12} {:<10}".format('Alloc.size', 'Occurrence'))
for allocation in top_heap_memory_allocations:
    (size, occurrence) = allocation
    print("{:<12} {:<10}".format(str(size) + ' KB', str(occurrence) + 'x'))
