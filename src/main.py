import argparse
import datetime
from utils import load_users, export_results
from attack_methods import run_bruteforce, run_dictionary, run_rainbow

def main():
    config = parse_arguments()
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


def parse_arguments():
    parser = argparse.ArgumentParser(description="Password Benchmarking Tool")
    parser.add_argument('user_file', help='File containing username:password/hash entries')
    parser.add_argument('method', choices=['bruteforce', 'dictionary', 'rainbow'], help='Cracking method to use')
    parser.add_argument('resource_file', nargs='?', help='Dictionary or rainbow table file')
    parser.add_argument('limit', nargs='?', help='Optional time limit (e.g., 60s)')

    args = parser.parse_args()

    limit_type = None
    limit_value = None

    if args.limit:
        if args.limit.endswith('s'):
            limit_type = 'time'
            limit_value = datetime.timedelta(seconds=int(args.limit[:-1]))
        if args.limit.endswith('m'):
            limit_type = 'time'
            limit_value = datetime.timedelta(minutes=int(args.limit[:-1]))

    return {
        'user_file': args.user_file,
        'method': args.method,
        'resource_file': args.resource_file,
        'limit_type': limit_type,
        'limit_value': limit_value,
        'max_length': 8, # max length of password to guess before failing
        'min_length': 1
    }


if __name__ == '__main__':
    main()
