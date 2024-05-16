#!/bin/bash

# Arguments: file to analyze, isolation directory
file_path="$1"
isolated_dir="$2"

# Check if the file exists
if [ ! -f "$file_path" ]; then
    echo "File not found: $file_path"
    exit 1
fi

# Create the isolation directory if it doesn't exist
mkdir -p "$isolated_dir"

# Perform basic syntactic analysis
# Count the number of lines, words, and characters
lines=$(wc -l < "$file_path")
words=$(wc -w < "$file_path")
chars=$(wc -m < "$file_path")

# Check for non-ASCII characters
non_ascii=$(grep -P '[^\x00-\x7F]' "$file_path")

# Check for specific keywords indicating potential malicious content
keywords=("corrupted" "dangerous" "risk" "attack" "malware" "malicious")
found_keyword=0
for keyword in "${keywords[@]}"; do
    if grep -qi "$keyword" "$file_path"; then
        found_keyword=1
        break
    fi
done

# Evaluate if the file is dangerous based on criteria
if [ "$lines" -lt 3 ] && [ "$words" -gt 1000 ] && [ "$chars" -gt 2000 ] || [ ! -z "$non_ascii" ] || [ $found_keyword -eq 1 ]; then
    echo "$file_path"
else
    echo "SAFE"
fi

exit 0
