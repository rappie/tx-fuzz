#!/usr/bin/env python3
"""
Analyze failed transaction JSON files and display unique error messages
sorted by frequency.

Usage:
    analyze_failures.py <directory>

Example:
    ./scripts/analyze_failures.py ./failed_txs
    ./scripts/analyze_failures.py ./failed_txs/20251102_173000
"""

import json
import sys
from pathlib import Path
from collections import Counter


def extract_error_message(json_file):
    """
    Extract the error message from a failed transaction JSON file.

    Returns the error message string or None if extraction fails.
    """
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)

        # Extract error.message field
        if 'error' in data and 'message' in data['error']:
            return data['error']['message']

        return None

    except (json.JSONDecodeError, IOError) as e:
        print(f"Warning: Failed to parse {json_file}: {e}", file=sys.stderr)
        return None


def main():
    # Check command-line arguments
    if len(sys.argv) != 2:
        print("Usage: analyze_failures.py <directory>", file=sys.stderr)
        print("\nExample:", file=sys.stderr)
        print("  ./scripts/analyze_failures.py ./failed_txs", file=sys.stderr)
        sys.exit(1)

    # Get directory path
    dir_path = Path(sys.argv[1])

    # Validate directory exists
    if not dir_path.exists():
        print(f"Error: Directory does not exist: {dir_path}", file=sys.stderr)
        sys.exit(1)

    if not dir_path.is_dir():
        print(f"Error: Path is not a directory: {dir_path}", file=sys.stderr)
        sys.exit(1)

    # Find all JSON files recursively
    json_files = list(dir_path.rglob("*.json"))

    if not json_files:
        print(f"No JSON files found in {dir_path}")
        sys.exit(0)

    print(f"Found {len(json_files)} JSON file(s) in {dir_path}\n")

    # Extract error messages
    error_messages = []
    for json_file in json_files:
        error_msg = extract_error_message(json_file)
        if error_msg:
            error_messages.append(error_msg)

    if not error_messages:
        print("No error messages found in any files")
        sys.exit(0)

    # Count occurrences
    error_counts = Counter(error_messages)

    # Display results sorted by frequency (most common first)
    print(f"Unique errors: {len(error_counts)}")
    print(f"Total failures: {len(error_messages)}\n")

    for error_msg, count in error_counts.most_common():
        print(f"{count}x {error_msg}")


if __name__ == "__main__":
    main()
