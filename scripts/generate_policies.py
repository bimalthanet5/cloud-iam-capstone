import json
import os

os.makedirs('policies', exist_ok=True)

# Vulnerable policies (with wildcards)
vulnerable_policies = [
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }]
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "arn:aws:s3:::*"
        }]
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "*"
        }]
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "ec2:*",
            "Resource": "*"
        }]
    }
]

# Safe policies (no wildcards)
safe_policies = [
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }]
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"],
            "Resource": "*"
        }]
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:us-east-1:123456789012:*"
        }]
    }
]

# Generate 100 policies
count = 0

# Add vulnerable ones multiple times
for i in range(30):
    for policy in vulnerable_policies:
        filename = f"policies/policy_{count}.json"
        with open(filename, 'w') as f:
            json.dump(policy, f, indent=2)
        count += 1

# Add safe ones
for i in range(20):
    for policy in safe_policies:
        filename = f"policies/policy_{count}.json"
        with open(filename, 'w') as f:
            json.dump(policy, f, indent=2)
        count += 1

print(f"Generated {count} policies!")
