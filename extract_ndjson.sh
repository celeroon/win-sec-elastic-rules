#!/bin/bash

# Create or clear the output files
POC_FILE="POC_RULES.ndjson"
PROD_FILE="PROD_RULES.ndjson"

> "$POC_FILE"
> "$PROD_FILE"

# Function to concatenate files and remove duplicates
concatenate_files() {
    local pattern=$1
    local output_file=$2
    local temp_file=$(mktemp)

    # Find and concatenate files matching the pattern into a temporary file
    find . -type f -name "$pattern" -print0 | while IFS= read -r -d '' file; do
        cat "$file" >> "$temp_file"
        echo >> "$temp_file"
    done

    # Remove duplicates and write to the output file
    awk '!seen[$0]++' "$temp_file" > "$output_file"
    rm "$temp_file"
}

# Concatenate POC-*.ndjson files into POC_RULES.ndjson
concatenate_files "POC-*.ndjson" "$POC_FILE"

# Concatenate PROD-*.ndjson files into PROD_RULES.ndjson
concatenate_files "PROD-*.ndjson" "$PROD_FILE"

echo "POC and PROD ndjson files have been combined into POC_RULES.ndjson and PROD_RULES.ndjson respectively, without duplicates."
