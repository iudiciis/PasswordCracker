import hashlib
import csv
import time

def load_users(filepath):
    """
    Loads user credentials from a file in username:password/hash format.
    
    Parses each line to extract username and target value (password or hash).
    
    Args:
        filepath: Path to file containing user credentials
        
    Returns:
        List of user dictionaries with username and target fields
    """
    users = []
    with open(filepath) as file:
        for line in file:
            if ':' not in line:
                continue
            username, value = line.strip().split(':', 1)
            users.append({'username': username, 'target': value})
    return users


def load_dict(filepath):
    """
    Loads a password dictionary from a text file.
    
    Reads each line as a potential password for dictionary-based attacks.
    
    Args:
        filepath: Path to dictionary file with one password per line
        
    Returns:
        List of password strings from the file
    """
    passwords = []
    with open(filepath) as file:
        for line in file:
            passwords.append(line)
    return passwords


def get_charset():
    """
    Returns the character set used for brute force password generation.
    
    Returns:
        String containing all characters used in brute force attacks
    """
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~'
    return charset


def export_results(results, config):
    """
    Displays cracking results in a formatted output.
    
    Shows different information based on the cracking method used:
    - Rainbow table: includes hash algorithm detection
    - Other methods: shows basic password cracking statistics
    
    Args:
        results: List of result dictionaries from cracking attempts
        config: Configuration dictionary containing method information
    """
    print("\nCracking Results:")
    if config['method'] == 'rainbow':
        for r in results:
            print(f"{r['username']} | Hash: {r['hash']} | Algorithm: {r.get('algorithm', 'Unknown')} | Password: {r.get('password', 'Not Found')} | Cracked: {r['cracked']} | Attempts: {r['attempts']} | Time: {r['time']:.2f}s")
    else:
        for r in results:
            print(f"{r['username']} | Password: {r.get('password', 'N/A')} | Cracked: {r['cracked']} | Attempts: {r['attempts']} | Time: {r['time']:.2f}s")


def generate_rainbow_table(input_file: str, output_file: str, algorithms: list[str]):
    """
    Creates a rainbow table CSV mapping plaintext passwords to multiple hash algorithms.
    
    Reads passwords from input file and generates corresponding hashes using the
    specified algorithms (MD5, SHA1, SHA256, SHA512, etc.). Outputs a CSV with
    plaintext and hash columns for fast hash-to-password lookups.

    Args:
        input_file: Path to file containing one plaintext password per line
        output_file: Path where the rainbow table CSV will be written
        algorithms: List of hash algorithm names to generate (e.g. ['md5', 'sha1'])
    """
    start_time = time.monotonic()
    with open(input_file, 'r', encoding='utf-8') as infile:
        passwords = [line.strip() for line in infile if line.strip()]

    with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        header = ['plaintext'] + algorithms
        writer.writerow(header)

        for password in passwords:
            row = [password]
            for algo in algorithms:
                try:
                    h = hashlib.new(algo)
                    h.update(password.encode('utf-8'))
                    row.append(h.hexdigest())
                except ValueError:
                    row.append(f"[unsupported:{algo}]")
            writer.writerow(row)
    
    total_time = time.monotonic() - start_time
    print(f"Processed {len(passwords)} passwords in {total_time} seconds.")

def load_rainbow_table(filepath: str):
    """
    Loads a rainbow table from CSV format into memory for hash lookups.
    
    Reads a CSV file containing plaintext passwords and their corresponding hashes
    across multiple algorithms. Each row becomes a dictionary mapping algorithm
    names to hash values.
    
    Args:
        filepath: Path to the rainbow table CSV file
        
    Returns:
        List of dictionaries, each containing plaintext and hash mappings
        (e.g. {'plaintext': 'password123', 'md5': '...', 'sha1': '...', ...})
    """
    table = []
    with open(filepath, newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            table.append({k.strip(): v.strip() for k, v in row.items()})
    return table
