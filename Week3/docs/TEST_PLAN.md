# Week 3 - Exploitation Test Plan

## Overview
Test exploitation of wildcard IAM policies in moto (AWS simulation).

## Test Environment
- VM: CloudSec-Testing (Kali Linux)
- Tool: moto (AWS API simulation)
- SDK: boto3 (Python AWS SDK)

## Test Policies
1. vulnerable_policy.json - Action:"*", Resource:"*"

## APIs to Test (15+)
### IAM APIs
- [ ] ListUsers
- [ ] ListRoles
- [ ] CreateRole
- [ ] AttachRolePolicy
- [ ] DeleteRole

### S3 APIs
- [ ] ListBuckets
- [ ] CreateBucket
- [ ] DeleteBucket

### EC2 APIs
- [ ] DescribeInstances
- [ ] RunInstances
- [ ] TerminateInstances

### Lambda APIs
- [ ] ListFunctions
- [ ] CreateFunction
- [ ] DeleteFunction

## Success Metrics
- Success: API call executes without permission error
- Failure: API call blocked/denied
- Target: 85%+ success rate to confirm hypothesis TRUE

## Timeline
- Setup moto: 30 min
- Write test script: 1-2 hours
- Run tests: 30 min
- Analyze results: 30 min
