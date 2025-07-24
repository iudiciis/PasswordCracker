from datetime import timedelta
import itertools
import time
from typing import Any
from multiprocessing import Process, Queue
from utils import get_charset, load_dict, load_rainbow_table

def run_bruteforce(users: list[dict[str, str]], config: list[dict[str, Any]]):
    """
    Performs brute force password cracking using parallel processes.
    
    Each process handles combinations starting with a different character from the charset,
    generating all possible password combinations up to max_length. Supports time-based
    limits to prevent infinite execution.
    
    Args:
        users: List of user dictionaries containing username and target password
        config: Configuration dictionary with max_length, limit_type, and limit_value
        
    Returns:
        List of result dictionaries containing cracking statistics for each user
    """
    charset = get_charset()
    max_length: int = config['max_length']
    limit_type: str = config['limit_type']
    end_results = []

    for user in users:
        if user['target'] is not None and len(user['target']) <= 2:
            end_result = {
                'username': user['username'],
                'password': user['target'],
                'cracked': False,
                'attempts': -1,
                'time': -1
            }

        result_queue = Queue()
        processes: list[Process] = []
        start = time.monotonic()
        attempt_queue = Queue()
        target_password = user['target']
        cracked = False
        curr_results = []
        time_limit = config['limit_value']

        incrementer = Process(target=attempt_incrementer, args=(attempt_queue,))
        incrementer.start()

        for prefix in charset:
            process = Process(target=run_bruteforce_worker, args=(target_password, prefix, attempt_queue, max_length, start, limit_type, time_limit, result_queue))
            process.start()
            processes.append(process)

        while len(curr_results) < len(processes):
            result = result_queue.get()
            curr_results.append(result)

            if result is not None and result == target_password:
                cracked = True
                break

        for process in processes:
            if process.is_alive():
                print("Process has terminated.")
                process.terminate()
                process.join(timeout=1)
                if process.is_alive():
                    process.kill()

        attempt_queue.put("STOP", block=True)
        total_attempts = 0
        while not attempt_queue.empty():
            try:
                attempts = attempt_queue.get(block=False)
                total_attempts += attempts
            except attempt_queue.empty():
                break

        incrementer.terminate()
        incrementer.join(timeout=1)
        if incrementer.is_alive():
            incrementer.kill()

        result_queue.close()
        attempt_queue.close()

        end_result = {
            'username': user['username'],
            'password': user['target'],
            'cracked': cracked,
            'attempts': total_attempts,
            'time': time.monotonic() - start
        }
        print(end_result)
        end_results.append(end_result)

    return end_results

def run_bruteforce_worker(password: str, prefix: str, attempts_queue: Queue, max_length: int, start: float, limit_type, time_limit: None | timedelta, result: Queue):
    """
    Worker process for brute force cracking that handles combinations starting with a specific prefix.
    
    Generates all possible password combinations of increasing length using the charset,
    checking each against the target password. Respects time limits and reports attempts
    back to the main process.
    
    Args:
        password: Target password to crack
        prefix: Starting character for this worker's combinations
        attempts_queue: Queue to report attempt counts
        max_length: Maximum password length to attempt
        start: Start time for timing calculations
        limit_type: Type of limit ('time' or other)
        time_limit: Time limit as timedelta object
        result: Queue to report cracking results
    """
    charset = get_charset().replace(prefix, "")

    try:
        print(f"Process {prefix} has started.")
        attempts = 0
        for length in range(1, max_length + 1):
            for char_combo in itertools.product(charset, repeat=length):
                guess = prefix + ''.join(char_combo)
                attempts += 1
                
                time_spent = time.monotonic() - start
                if limit_type == 'time' and time_limit and time_spent > time_limit.total_seconds():
                    print(f"Process {prefix} timed out.")
                    result.put(None)
                    attempts_queue.put(attempts)
                    return

                if guess == password:
                    print(f"Process {prefix} found {guess}.")
                    result.put(guess)
                    attempts_queue.put(attempts)
                    return

        print(f"Process {prefix} exhausted all combinations.")
        result.put(None)
        attempts_queue.put(attempts)
        return
    except Exception as e:
        print(f"Process {prefix} encountered error: {e}")
        result.put(None)
        attempts_queue.put(attempts)
        return

def attempt_incrementer(queue: Queue):
    """
    Background process that aggregates attempt counts from all worker processes.
    
    Continuously receives attempt counts from workers and maintains a running total
    until receiving a STOP signal, then returns the final count.
    
    Args:
        queue: Queue for receiving attempt counts and sending final total
    """
    attempts = 0
    try:
        while True:
            message = queue.get()
            if message == "STOP":
                queue.put(attempts)
                break
            elif isinstance(message, int):
                attempts += message
    except Exception as e:
        print(f"Incrementer error: {e}")
        queue.put(attempts)
    return


def run_dictionary(users: list[dict[str, str]], config: list[dict[str, Any]]):
    """
    Performs dictionary-based password cracking by testing passwords from a wordlist.
    
    Sequentially tries each password from the dictionary file against each user's
    target password. Supports time limits to prevent excessive execution time.
    
    Args:
        users: List of user dictionaries containing username and target password
        config: Configuration dictionary with resource_file, limit_type, and limit_value
        
    Returns:
        List of result dictionaries containing cracking statistics for each user
    """
    dictionary: list[str] = load_dict(config['resource_file'])
    end_results = []
    limit_type: str = config['limit_type']
    time_limit: timedelta = config['limit_value']

    for user in users:
        start = time.monotonic()
        attempts = 0
        cracked = False
        target: str = user['target']
        for password in dictionary:
            attempts += 1
            if password.rstrip() == target:
                cracked = True
                break

            time_spent = time.monotonic() - start
            if limit_type == 'time' and time_limit and time_spent > time_limit.total_seconds():
                break

        result = {
            'username': user['username'],
            'password': user['target'],
            'cracked': cracked,
            'attempts': attempts,
            'time': time.monotonic() - start
        }
        end_results.append(result)
    return end_results


def run_rainbow(users: list[dict[str, str]], config: list[dict[str, Any]]):
    """
    Performs rainbow table-based password cracking by looking up hashes in precomputed tables.
    
    Searches through a rainbow table containing plaintext passwords and their corresponding
    hashes across multiple algorithms (MD5, SHA1, SHA256, etc.) to find matches for the
    target hashes.
    
    Args:
        users: List of user dictionaries containing username and target hash
        config: Configuration dictionary with resource_file path to rainbow table
        
    Returns:
        List of result dictionaries containing hash algorithm, plaintext password, and statistics
    """
    rainbow = load_rainbow_table(config['resource_file'])
    hash_algos = rainbow[0].keys() - {'plaintext'}

    end_results = []
    for user in users:
        attempts = 0
        start = time.monotonic()
        cracked = False
        password_found = 'Not Found'
        hash_algorithm = 'Unknown'

        for entry in rainbow:
            for algo in hash_algos:
                attempts += 1
                if user['target'] == entry[algo]:
                    hash_algorithm = algo
                    cracked = True
                    password_found = entry['plaintext']
                    break
            if cracked:
                break

        end_results.append({
            'username': user['username'],
            'cracked': cracked,
            'algorithm': hash_algorithm,
            'password': password_found,
            'hash': user['target'],
            'attempts': attempts,
            'time': time.monotonic() - start
        })
    return end_results