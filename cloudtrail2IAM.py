import argparse
import boto3
import gzip
import json
import tempfile
from tqdm import tqdm
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore

ALL_ACTIONS: Dict[str, List[str]] = {}
semaphore = Semaphore()

def get_s3_client(profile: str):
    """Create an S3 client using the specified profile."""
    session = boto3.Session(profile_name=profile)
    return session.client('s3')

def download_log_file(s3_client, bucket: str, key: str, local_path: str):
    """Download the log file from the specified S3 bucket and key to a local path."""
    s3_client.download_file(bucket, key, local_path)

def fix_arn(arn: str) -> str:
    """Fix the ARN to remove the role name from the path."""
    if arn.startswith('arn:aws:sts::'):
        arn = arn.replace('arn:aws:sts::', 'arn:aws:iam::')
        arn = arn.replace('assumed-role', 'role')
        arn = "/".join(arn.split("/")[:2])
    
    return arn


def extract_actions_from_log_file(file_path: str):
    """Extract actions performed by the target role or user from the downloaded log file."""
    global ALL_ACTIONS
    global semaphore

    with gzip.open(file_path, 'rt', encoding='utf-8') as file:
        data = json.load(file)
        for record in data.get('Records', []):
            if 'userIdentity' in record and 'arn' in record['userIdentity']:
                arn = fix_arn(record['userIdentity']['arn'])
                action = record['eventSource'].split(".")[0] + " - " + record['eventName']
                with semaphore:
                    if not ALL_ACTIONS.get(arn):
                        ALL_ACTIONS[arn] = set([action])
                    else:
                        ALL_ACTIONS[arn].add(action)

def get_all_keys(s3_client, bucket_name: str, prefix: str) -> List[Dict[str, Any]]:
    """List all objects with the specified prefix in the S3 bucket."""
    logs_list = []
    paginator = s3_client.get_paginator('list_objects_v2')

    # The max is 1000...
    for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix, MaxKeys=1000):
        if 'Contents' in page:
            logs_list.extend(page['Contents'])
            print("Found {} logs".format(len(logs_list)), end='\r')

    print()
    return logs_list

def process_log_object(s3_client, bucket_name: str, log_obj: Dict[str, Any]):
    """Download and process each log file."""
    log_key = log_obj['Key']
    if ".json.gz" not in log_key or "digest" in log_key.lower():
        return

    with tempfile.NamedTemporaryFile() as temp_file:
        download_log_file(s3_client, bucket_name, log_key, temp_file.name)
        extract_actions_from_log_file(temp_file.name)

def main():
    global ALL_ACTIONS

    parser = argparse.ArgumentParser(description='Analyze CloudTrail logs for specific actions')
    parser.add_argument('--prefix', required=True, help='The S3 prefix for CloudTrail logs')
    parser.add_argument('--bucket_name', required=True, help='The S3 bucket name containing CloudTrail logs')
    parser.add_argument('--profile', required=True, help='The AWS profile to use for accessing the S3 bucket')
    parser.add_argument('--threads', type=int, default=10, help='The number of threads to use for processing log files')
    parser.add_argument('--filter-name', required=False, help='Only get actions performed by this name')
    args = parser.parse_args()

    target_name = args.filter_name

    s3_client = get_s3_client(args.profile)

    logs_list = get_all_keys(s3_client, args.bucket_name, args.prefix)

    # Use ThreadPoolExecutor to process log files with the specified number of threads
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(process_log_object, s3_client, args.bucket_name, log_obj) for log_obj in logs_list]
        for future in tqdm(as_completed(futures), total=len(futures), desc="Cloudtrail files"):
            future.result()
    
    # Fiter by name if specified
    if target_name:
        all_actions_temp = {}
        for arn, actions in ALL_ACTIONS.items():
            if target_name in arn:
                all_actions_temp[arn] = actions
        ALL_ACTIONS = all_actions_temp

    for arn, actions in ALL_ACTIONS.items():
        print(f'Actions performed by {arn}')
        actions = sorted(actions)
        for action in actions:
            print(f"- {action}")

if __name__ == '__main__':
    main()