import hashlib
import json
import csv
from typing import Dict, List
import time

def load_users(filepath):
    users = []
    with open(filepath) as file:
        for line in file:
            if ':' not in line:
                continue
            username, value = line.strip().split(':', 1)
            is_hash = len(value) > 10
            users.append({'username': username, 'target': value, 'is_hash': is_hash})
    return users


def load_dict(filepath):
    passwords = []
    with open(filepath) as file:
        for line in file:
            passwords.append(line)
    return passwords


def get_charset():
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&\'()*+,-./:;<=>?@[\]^_`{|}~'
    return charset


def export_results(results, config):
    print("\nCracking Results:")
    for r in results:
        print(f"{r['username']} | Password: {r.get('password', 'N/A')} | Cracked: {r['cracked']} | Attempts: {r['attempts']} | Time: {r['time']:.2f}s")


def generate_rainbow_table(password_file: str, output_format: str = 'json', hash_types: List[str] = None):
    """
    Generate rainbow table from a password list.
    
    Args:
        password_file: Path to text file with passwords (one per line)
        output_format: 'json', 'csv', or 'dict' (returns dictionary)
        hash_types: List of hash algorithms to use (default: common ones)
    
    Returns:
        Dictionary mapping hashes to passwords (if output_format='dict')
    """
    
    if hash_types is None:
        hash_types = ['md5', 'sha1', 'sha256', 'sha512']
    
    rainbow_tables = {hash_type: {} for hash_type in hash_types}
    
    print(f"Reading passwords from {password_file}...")
    
    try:
        with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File {password_file} not found")
        return None
    
    print(f"Processing {len(passwords)} passwords...")
    start_time = time.time()
    
    for i, password in enumerate(passwords):
        # Show progress every 10,000 passwords
        if i % 10000 == 0 and i > 0:
            elapsed = time.time() - start_time
            rate = i / elapsed
            print(f"Processed {i}/{len(passwords)} passwords ({rate:.0f} passwords/sec)")
        
        for hash_type in hash_types:
            if hash_type == 'md5':
                hash_value = hashlib.md5(password.encode('utf-8')).hexdigest()
            elif hash_type == 'sha1':
                hash_value = hashlib.sha1(password.encode('utf-8')).hexdigest()
            elif hash_type == 'sha256':
                hash_value = hashlib.sha256(password.encode('utf-8')).hexdigest()
            elif hash_type == 'sha512':
                hash_value = hashlib.sha512(password.encode('utf-8')).hexdigest()
            else:
                continue
            
            # Store hash -> password mapping
            rainbow_tables[hash_type][hash_value] = password
    
    total_time = time.time() - start_time
    print(f"Generated rainbow tables in {total_time:.2f} seconds")
    
    # Output based on format
    if output_format == 'dict':
        return rainbow_tables
    
    elif output_format == 'json':
        for hash_type in hash_types:
            filename = f"rainbow_table_{hash_type}.json"
            with open(filename, 'w') as f:
                json.dump(rainbow_tables[hash_type], f, indent=2)
            print(f"Saved {len(rainbow_tables[hash_type])} {hash_type} hashes to {filename}")
    
    elif output_format == 'csv':
        for hash_type in hash_types:
            filename = f"rainbow_table_{hash_type}.csv"
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['hash', 'password'])
                for hash_value, password in rainbow_tables[hash_type].items():
                    writer.writerow([hash_value, password])
            print(f"Saved {len(rainbow_tables[hash_type])} {hash_type} hashes to {filename}")
    
    return rainbow_tables

def load_rainbow_table(filename: str, file_format: str = 'json') -> Dict[str, str]:
    """Load rainbow table from file."""
    if file_format == 'json':
        with open(filename, 'r') as f:
            return json.load(f)
    elif file_format == 'csv':
        rainbow_table = {}
        with open(filename, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rainbow_table[row['hash']] = row['password']
        return rainbow_table
