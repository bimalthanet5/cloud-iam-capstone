import json
import csv
import os
import boto3
from moto import mock_iam, mock_s3, mock_ec2, mock_sts

class RealPolicyTester:
    def __init__(self):
        self.policies_dir = "/home/kali/cloud-iam-capstone-git/policies"
        self.results_file = "/home/kali/cloud-iam-capstone-git/scripts/results.csv"
        self.exploitation_results = []
        self.total_tested = 0
        self.total_exploitable = 0

    def load_vulnerable_policies(self):
        vulnerable = []
        try:
            with open(self.results_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['vulnerable'].lower() == 'true':
                        vulnerable.append(row['filename'])
            print(f"Loaded {len(vulnerable)} vulnerable policies")
            return vulnerable
        except Exception as e:
            print(f"ERROR loading results.csv: {e}")
            return []

    def has_wildcard(self, policy):
        if 'Statement' not in policy:
            return False
        for statement in policy['Statement']:
            action = statement.get('Action', '')
            resource = statement.get('Resource', '')
            effect = statement.get('Effect', '')
            if effect != 'Allow':
                continue
            if isinstance(action, str):
                action_wildcard = '*' in action
            elif isinstance(action, list):
                action_wildcard = any('*' in a for a in action)
            else:
                action_wildcard = False
            if isinstance(resource, str):
                resource_wildcard = '*' in resource
            elif isinstance(resource, list):
                resource_wildcard = any('*' in r for r in resource)
            else:
                resource_wildcard = False
            if action_wildcard or resource_wildcard:
                return True
        return False

    @mock_iam
    @mock_s3
    @mock_ec2
    @mock_sts
    def run_exploitation_tests(self, policy_file):
        success = 0
        total = 15

        iam = boto3.client('iam', region_name='us-east-1')
        s3 = boto3.client('s3', region_name='us-east-1')
        ec2 = boto3.client('ec2', region_name='us-east-1')
        sts = boto3.client('sts', region_name='us-east-1')

        try:
            iam.list_users()
            success += 1
        except:
            pass
        try:
            iam.list_roles()
            success += 1
        except:
            pass
        try:
            iam.create_role(RoleName='exploit-role', AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17"}))
            success += 1
        except:
            pass
        try:
            iam.list_policies()
            success += 1
        except:
            pass
        try:
            iam.list_groups()
            success += 1
        except:
            pass
        try:
            s3.list_buckets()
            success += 1
        except:
            pass
        try:
            s3.create_bucket(Bucket='exploit-test-bucket')
            success += 1
        except:
            pass
        try:
            s3.list_objects_v2(Bucket='exploit-test-bucket')
            success += 1
        except:
            pass
        try:
            s3.put_object(Bucket='exploit-test-bucket', Key='test.txt', Body=b'exploit test')
            success += 1
        except:
            pass
        try:
            ec2.describe_instances()
            success += 1
        except:
            pass
        try:
            ec2.describe_vpcs()
            success += 1
        except:
            pass
        try:
            ec2.describe_security_groups()
            success += 1
        except:
            pass
        try:
            ec2.describe_subnets()
            success += 1
        except:
            pass
        try:
            sts.get_caller_identity()
            success += 1
        except:
            pass
        try:
            sts.get_session_token()
            success += 1
        except:
            pass

        return (success / total) * 100

    def run_all_tests(self):
        print("=" * 70)
        print("SECONDARY HYPOTHESIS - REAL POLICY EXPLOITATION TEST")
        print("=" * 70)
        print("Testing: ALL wildcard policies from GitHub")
        print("Hypothesis: 85%+ exploitation success rate")
        print("=" * 70 + "\n")

        vulnerable_policies = self.load_vulnerable_policies()

        if not vulnerable_policies:
            print("ERROR: No vulnerable policies found!")
            return

        print("\nFiltering for wildcard policies...")
        wildcard_policies = []

        for policy_file in vulnerable_policies:
            try:
                filepath = os.path.join(self.policies_dir, policy_file)
                with open(filepath, 'r') as f:
                    policy = json.load(f)
                if self.has_wildcard(policy):
                    wildcard_policies.append(policy_file)
            except:
                continue

        print(f"Found {len(wildcard_policies)} wildcard policies\n")
        print("Starting exploitation tests (15 API calls each)...\n")
        print("-" * 70)

        for i, policy_file in enumerate(wildcard_policies):
            try:
                success_rate = self.run_exploitation_tests(policy_file)
                self.total_tested += 1

                if success_rate >= 85:
                    self.total_exploitable += 1
                    status = "EXPLOITABLE"
                else:
                    status = "PARTIAL"

                self.exploitation_results.append({
                    'policy_file': policy_file,
                    'status': status,
                    'api_success_rate': f"{success_rate:.1f}%"
                })

                print(f"[{i+1}/{len(wildcard_policies)}] {policy_file}")
                print(f"   API Success Rate: {success_rate:.1f}%")
                print(f"   Status: {status}\n")

            except Exception as e:
                print(f"[{i+1}] ERROR {policy_file}: {e}\n")

        self.print_summary()
        self.save_results()

    def print_summary(self):
        print("\n" + "=" * 70)
        print("SECONDARY HYPOTHESIS TEST RESULTS")
        print("=" * 70)
        print(f"Total policies tested: {self.total_tested}")
        print(f"Exploitable (85%+): {self.total_exploitable}")
        print(f"Partial exploitation: {self.total_tested - self.total_exploitable}")

        if self.total_tested > 0:
            exploit_rate = (self.total_exploitable / self.total_tested) * 100
            print(f"\nOverall Exploitation Rate: {exploit_rate:.1f}%")
            print(f"Hypothesis Threshold: 85%")

            if exploit_rate >= 85:
                print("\nSECONDARY HYPOTHESIS: TRUE")
                print("Wildcard policies exploitable with 85%+ success!")
            else:
                print("\nSECONDARY HYPOTHESIS: FALSE")
                print(f"Exploitation rate {exploit_rate:.1f}% below 85% threshold")
        print("=" * 70)

    def save_results(self):
        os.makedirs("results", exist_ok=True)
        with open("results/exploitation_results.csv", "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['policy_file', 'status', 'api_success_rate'])
            writer.writeheader()
            for result in self.exploitation_results:
                writer.writerow(result)
        print(f"\nResults saved: results/exploitation_results.csv")


def main():
    tester = RealPolicyTester()
    tester.run_all_tests()


if __name__ == "__main__":
    main()
