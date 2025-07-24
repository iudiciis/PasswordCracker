import argparse
import datetime
from utils import generate_rainbow_table, load_users, export_results
from attack_methods import run_bruteforce, run_dictionary, run_rainbow

def main():
    """
    Main entry point for the password benchmarking tool.
    
    Parses command line arguments and executes either rainbow table creation
    or password cracking benchmarks using the specified method (brute force,
    dictionary, or rainbow table lookup).
    """
    config = parse_arguments()
    if config['command'] == 'create_rainbow':
        generate_rainbow_table(config['resource_file'], config['dest_file'], ['md5', 'sha1', 'sha256', 'sha512'])

    elif config['command'] == 'benchmark':
        users = load_users(config['user_file'])
        if config['method'] == 'bruteforce':
            results = run_bruteforce(users, config)
        elif config['method'] == 'dictionary':
            results = run_dictionary(users, config)
        elif config['method'] == 'rainbow':
            results = run_rainbow(users, config)
        else:
            raise ValueError(f"Unknown method: {config['method']}")

        export_results(results, config)
    
    else:
        raise ValueError(f"Unknown command: {config['command']}")


def parse_arguments():
    """
    Parses and validates command line arguments for the password benchmarking tool.
    
    Supports two main commands:
    - 'benchmark': Test password strength using various cracking methods
    - 'create_rainbow': Generate rainbow tables from password lists
    
    For benchmark command, supports time limits specified with 's' or 'm' (e.g. 60s or 5m).
    
    Returns:
        Dictionary containing parsed configuration options including command type,
        file paths, method selection, and time limits
    """
    parser = argparse.ArgumentParser(description="Password Benchmarking Tool")
    subparsers = parser.add_subparsers(dest='command', help='Method to run')

    parser_benchmarking = subparsers.add_parser('benchmark', help='Benchmark your passwords')
    parser_benchmarking.add_argument('user_file', help='File containing username:password/hash entries')
    parser_benchmarking.add_argument('method', choices=['bruteforce', 'dictionary', 'rainbow'], help='Cracking method to use')
    parser_benchmarking.add_argument('resource_file', nargs='?', help='Dictionary or rainbow table file')
    parser_benchmarking.add_argument('limit', nargs='?', help='Optional time limit (e.g., 60s)')

    parser_createdict = subparsers.add_parser('create_rainbow', help='Create a new rainbow table')
    parser_createdict.add_argument('resource_file', help='Password list to create a rainbow table from')
    parser_createdict.add_argument('dest_file', help='What file to write to')

    args = parser.parse_args()

    limit_type = None
    limit_value = None

    if args.command == "benchmark":
        if args.limit and args.limit.endswith('s'):
            limit_type = 'time'
            limit_value = datetime.timedelta(seconds=int(args.limit[:-1]))
        if args.limit and args.limit.endswith('m'):
            limit_type = 'time'
            limit_value = datetime.timedelta(minutes=int(args.limit[:-1]))
        return {
            'command': args.command,
            'user_file': args.user_file,
            'method': args.method,
            'resource_file': args.resource_file,
            'limit_type': limit_type,
            'limit_value': limit_value,
            'max_length': 8, # max length of password to guess before failing
            'min_length': 1
        }
    elif args.command == "create_rainbow":
        return {
            'command': args.command,
            'resource_file': args.resource_file,
            'dest_file': args.dest_file
        }


if __name__ == '__main__':
    main()
