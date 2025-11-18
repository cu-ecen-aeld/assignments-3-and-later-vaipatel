#!/bin/bash

SCRIPT_NAME=$(basename "$0")
usage() {
	echo "Usage: $SCRIPT_NAME DIRECTORY SEARCHSTRING"
	echo "Searches files in DIRECTORY for SEARCHSTRING. Returns the number of matching files and lines."
	echo ""
	echo "Arguments:"
	echo "  DIRECTORY        Directory to search in, recursively"
	echo "  SEARCHSTRING     String to search for"
	echo ""
	exit 1
}

filesdir=$1
searchstr=$2

if [[ -z $filesdir || -z $searchstr ]]; then
	usage
fi

if [[ ! -d $filesdir ]]; then
	echo "$filesdir cannot be found. Please make sure the directory exists." >&2
	exit 1
fi

# To get the number of matching files, we tell grep to look recursively with -r
# and return the match count with -c. Also we ignore error messages with -s to
# avoid counting error prints as files. If we now count the newlines we have
# using `wc -l`, we should get the number of files `grep -r` considered.
num_files=$(grep -rc -s "$searchstr" "$filesdir" | wc -l)

# If we do what we did above, but instead of getting a match count with -c we
# print all the matches per file with -o, and now count the newlines, we should
# get the total number of matches in all the files that `grep -r` considered.
num_matches=$(grep -ro -s "$searchstr" "$filesdir" | wc -l)

echo "The number of files are $num_files and the number of matching lines are $num_matches"
