# Cloudtrail2IAM

CloudTrail2IAM is a Python tool that analyzes **AWS CloudTrail logs to extract and summarize actions** done by everyone or just an specific user or role. The tool will **parse every cloudtrail log from the indicated bucket**.

This is useful for red teamers that have **read access over Cloudtrail logs and wants to have more info about the permissions** of the roles and users but **doesn't have read access over IAM**.

*Note that a Cloudtrail bucket might contain hundreds of thousands of log files. So this could take several minutes.*

## Installation

```sh
git clone https://github.com/carlospolop/Cloudtrail2IAM
cd Cloudtrail2IAM
pip install -r requirements.txt
python3 cloudtrail2IAM.py --prefix PREFIX --bucket_name BUCKET_NAME --profile PROFILE [--filter-name FILTER_NAME] [--threads THREADS]
```
