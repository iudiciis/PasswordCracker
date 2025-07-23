from datetime import timedelta
import itertools
import time
from typing import Any
from multiprocessing import Process, Queue
from utils import get_charset, load_dict, load_rainbow_table

def run_bruteforce(users: list[dict[str, str]], config: list[dict[str, Any]]):
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
    rainbow = load_rainbow_table(config['resource_file'])
    hash_algos = rainbow[0].keys() - {'plaintext'}

    attempts = 0
    end_results = []
    for user in users:
        start = time.time()
        cracked = False
        password_found = None

        for entry in rainbow:
            for algo in hash_algos:
                attempts += 1
                if user['target'] == entry[algo]:
                    cracked = True
                    password_found = entry['plaintext']
                    break
            if cracked:
                break

        end_results.append({
            'username': user['username'],
            'cracked': cracked,
            'password': password_found,
            'attempts': attempts,
            'time': time.time() - start
        })
    return end_results