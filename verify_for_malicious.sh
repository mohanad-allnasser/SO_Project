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
# Check for non-ASCII characters
if grep -qP '[^\x00-\x7F]' "$file_path"; then
    echo "Non-ASCII characters found in $file_path"
    mv "$file_path" "$isolated_dir/"
    exit 0
fi

# Check for specific keywords indicating potential malicious content
keywords=("corrupted" "dangerous" "risk" "attack" "malware" "malicious")
for keyword in "${keywords[@]}"; do
    if grep -qi "$keyword" "$file_path"; then
        echo "Keyword '$keyword' found in $file_path"
        mv "$file_path" "$isolated_dir/"
        exit 0
    fi
done

#why lines and words count?

echo "File analysis completed for $file_path:"
echo "Lines: $lines, Words: $words, Characters: $chars"

# If no suspicious indicators are found, the file is not moved
echo "No malicious indicators found in $file_path"
exit 0
 
