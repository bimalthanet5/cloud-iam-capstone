# Week 3 - Setup Guide

## Prerequisites
- Kali Linux VM (CloudSec-Testing) running
- Python 3 installed
- Virtual environment ready

## Installation Steps

### 1. Create Virtual Environment
```bash
cd ~/cloud-iam-capstone/week3-exploitation
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Required Libraries
```bash
pip install moto boto3 botocore
```

### 3. Verify Installation
```bash
python3 -c "import moto; import boto3; print('OK')"
```

## Project Structure
- `scripts/` - All Python test scripts
- `policies/` - IAM policy JSON files
- `results/` - Test output and results
- `docs/` - Documentation

## Running Tests
```bash
cd ~/cloud-iam-capstone/week3-exploitation
source venv/bin/activate
python3 scripts/exploit_tester.py
```

## Troubleshooting
If issues occur, check:
1. Virtual env activated: `echo $VIRTUAL_ENV`
2. Moto installed: `pip list | grep moto`
3. Boto3 working: `python3 -c "import boto3"`
