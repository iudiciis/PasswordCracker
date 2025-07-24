import hashlib
import csv
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
    if config['method'] == 'rainbow':
        for r in results:
            print(f"{r['username']} | Hash: {r['hash']} | Algorithm: {r.get('algorithm', 'Unknown')} | Password: {r.get('password', 'Not Found')} | Cracked: {r['cracked']} | Attempts: {r['attempts']} | Time: {r['time']:.2f}s")
    else:
        for r in results:
            print(f"{r['username']} | Password: {r.get('password', 'N/A')} | Cracked: {r['cracked']} | Attempts: {r['attempts']} | Time: {r['time']:.2f}s")


def generate_rainbow_table(input_file: str, output_file: str, algorithms: list[str]):
    """
    Create a rainbow table CSV mapping plaintext passwords to multiple hashes.

    Parameters:
    - input_file: path to file with one plaintext password per line
    - output_file: path to the CSV to write
    - algorithms: list of hashing algorithms (e.g. ['md5', 'sha1', 'sha256'])
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
    Loads a rainbow table CSV into a list of mappings:
    Each row is a dict like:
    {'plaintext': 'password123', 'md5': '...', 'sha1': '...', ...}
    """
    table = []
    with open(filepath, newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            table.append({k.strip(): v.strip() for k, v in row.items()})
    return table
