# Password Benchmarking Tool

A Python-based password strength testing tool that evaluates the security of passwords using three different attack methods: brute force, dictionary attacks, and rainbow table lookups.

*Disclaimer: This README file was written with some assistance from generative AI for the purposes of wording and sentence structure, as well as grammar. Additionally, the code for this tool was also mostly documented with the assistance of AI, however all code was not itself generated with AI tools.*

**This tool is for educational and authorized security testing purposes only.** Only use this tool on:
- Your own passwords and systems
- Systems you own or have explicit written permission to test
- Authorised penetration testing engagements

Unauthorised password cracking is illegal in most jurisdictions. We are not responsible for any misuse of this software.

## Features

- **Multiple Attack Methods**:
  - Brute force with parallel processing
  - Dictionary-based attacks
  - Rainbow table lookups
- **Performance Benchmarking**: Track attempts, success rates, and time taken
- **Hash Algorithm Support**: MD5, SHA1, SHA256, SHA512
- **Time Limits**: Configurable timeouts to prevent excessive resource usage
- **Rainbow Table Generation**: Create custom rainbow tables from password lists

## Requirements

- Python 3.7+
- Standard library modules (no external dependencies)

## Installation

1. Clone or download the repository:
```bash
git clone https://github.com/iudiciis/PasswordCracker.git
cd password-benchmarking-tool
```

2. Ensure you have Python 3.7+ installed:
```bash
python --version
```

## Usage

The tool supports two main commands: `benchmark` for testing passwords and `create_rainbow` for generating rainbow tables.

### Benchmarking Passwords

#### Basic Syntax
```bash
python main.py benchmark <user_file> <method> [resource_file] [time_limit]
```

#### Methods Available
- `bruteforce` - Systematic generation of all possible combinations
- `dictionary` - Test against a wordlist of common passwords  
- `rainbow` - Hash lookup using precomputed rainbow tables

#### Examples

**Brute Force Attack:**
```bash
python main.py benchmark users.txt bruteforce 60s
```

**Dictionary Attack:**
```bash
python main.py benchmark users.txt dictionary rockyou.txt 5m
```

**Rainbow Table Attack:**
```bash
python main.py benchmark users.txt rainbow rainbow_table.csv
```

### Creating Rainbow Tables

Generate rainbow tables from password lists:

```bash
python main.py create_rainbow passwords.txt rainbow_output.csv
```

This creates a CSV file with plaintext passwords and their MD5, SHA1, SHA256, and SHA512 hashes.

## File Formats
Example files can be found in the `data` folder.

### User File Format
Create a text file with username:password or username:hash pairs, one per line:

```
alice:password123
bob:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
charlie:letmein
```

### Dictionary File Format
Plain text file with one password per line:
```
password
123456
password123
admin
letmein
```

### Rainbow Table Format
CSV file with plaintext and hash columns:
```csv
plaintext,md5,sha1,sha256,sha512
password,5f4dcc3b5aa765d61d8327deb882cf99,5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8,...
123456,e10adc3949ba59abbe56e057f20f883e,7c4a8d09ca3762af61e59520943dc26494f8941b,...
```

## Configuration Options

### Time Limits
- `s` - seconds (e.g. 60s)
- `m` - minutes (e.g. 2m)
- No limit if not specified

### Brute Force Settings
- Maximum password length: 8 characters (configurable in code)
- Character set: Letters (a-z, A-Z), digits (0-9), and most commonly used symbols
- Parallel processing using multiple CPU cores

## Output Format

The tool displays results showing:
- Username
- Target password/hash
- Whether cracking succeeded
- Number of attempts made
- Time elapsed
- For rainbow tables: detected hash algorithm

Example output:
```
alice | Password: password123 | Cracked: True | Attempts: 1547 | Time: 0.23s
bob | Hash: 5f4dcc3b5aa765d61d8327deb882cf99 | Algorithm: md5 | Password: password | Cracked: True | Attempts: 892 | Time: 0.15s
```

## Performance Considerations

### Brute Force
- Exponentially increases with password length
- Uses parallel processing for better performance
- 8+ character passwords may take extremely long (CPU dependent)

### Dictionary Attacks
- Speed depends on dictionary size
- Most effective against common passwords
- Limited to passwords in the dictionary

### Rainbow Tables
- Requires precomputed tables (storage intensive)
- Limited to passwords in the original wordlist


## Limitations

- Brute force limited to 8 characters by default
- Dictionary attacks only as good as the wordlist
- Rainbow tables require significant storage space
- No support for advanced password policies or salt handling
- Single-threaded dictionary and rainbow table methods


## Changelog

### Version 1.0
- Initial release
- Brute force, dictionary, and rainbow table support
- Parallel processing for brute force attacks
- Rainbow table generation utility
