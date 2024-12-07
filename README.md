# FTP Login Checker

## Input
- **domains.txt**: List of domain names to check.

## Output
- **good.txt**: List of successful logins with files retrieved from the FTP server in the format `domain - user:password | Files: file1, file2, ....`
- **bad.txt**: List of domains where login attempts failed.

## Usage
1. Place domain names in `domains.txt`
2. Run the script.

The script checks FTP servers on port 21 for valid logins and retrieves directory listings. Results are written to `good.txt` for successful logins, and `bad.txt` for failures.

## Requirements
- Python 3.x
- colorama 