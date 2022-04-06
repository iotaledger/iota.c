#!/bin/sh

helpFunction()
{
   echo ""
   echo "Usage: $0 executable_file"
   exit 1 # Exit script after printing help
}

# Print helpFunction in case a parameter is missing
if [ -z "$1" ]
then
   echo "Executable file is missing";
   helpFunction
fi

# Begin script in case executable file is present
executable_file=$1

echo "Executing memory benchmark for: $executable_file\n"

echo "Memory benchmark with time and a verbose output:"
/bin/time -v $executable_file


