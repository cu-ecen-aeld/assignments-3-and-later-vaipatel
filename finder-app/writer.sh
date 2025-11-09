#!/bin/bash

SCRIPT_NAME=$(basename "$0")
usage() {
	echo "Usage: $SCRIPT_NAME WRITEFILE WRITESTR"
	echo "Writes a string to a new or existing file. Overwrites existing content."
	echo ""
	echo "Arguments:"
	echo "  WRITEFILE	New of existing file to write to"
	echo "  WRITESTR	String to write into WRITEFILE. Existing content will be overwritten"
	echo ""
	exit 1
}

writefile=$1
writestr=$2

if [[ -z $writefile || -z $writestr ]]; then
	usage
fi

# First ensure the directory exists 
# -p means "no error if existing, make parent directories as needed"
writefile_dir=$(dirname "$writefile")
mkdir -p "$writefile_dir"
# Check the exit status of the mkdir
if [[ $? -ne 0 ]]; then
	2>&1 echo "Could not create the directory '$writefile_dir'"
	exit 1
fi

# Now create the file AND echo to it
echo "$writestr" > "$writefile"
# Check the exit status of the echo and redirect
if [[ $? -ne 0 ]]; then
	2>&1 echo "Could not write to file '$writefile'"
	exit 1
fi

