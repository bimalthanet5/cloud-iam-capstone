import requests
import json
import os
import time
import hashlib
import socket
from pathlib import Path
from typing import List, Dict, Set

def check_internet_connection(max_wait_time=3600):
    """
    Check if internet is available. If not, wait until it returns.
    
    Args:
        max_wait_time (int): Maximum seconds to wait (default 1 hour)
    """
    wait_time = 0
    check_interval = 5  # Check every 5 seconds
    
    while True:
        try:
            # Try to connect to Google DNS (reliable check)
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True  # Internet is back!
        except (socket.timeout, socket.error):
            # No internet
            if wait_time == 0:
                print(f"\nWARNING: Internet connection lost!")
                print(f"Scraper paused. Waiting for internet to return...")
            
            # Wait and check again
            time.sleep(check_interval)
            wait_time += check_interval
            
            # Print status every 30 seconds
            if wait_time % 30 == 0:
                minutes = wait_time // 60
                print(f"   Still waiting... ({minutes} minutes elapsed)")
            
            # Timeout after max_wait_time
            if wait_time >= max_wait_time:
                print(f"\nERROR: Internet down for more than {max_wait_time} seconds!")
                print(f"Exiting scraper.")
                return False

class GitHubPolicyScraper:
    """
    Scraper to collect AWS IAM policies from GitHub repositories.
    Prevents duplicate policies and can be run multiple times safely.
    Pauses if internet connection is lost and resumes automatically.
    """
    
    def __init__(self, token: str):
        """
        Initialize the scraper with GitHub API authentication.
        
        Args:
            token (str): GitHub personal access token for API authentication
        """
        self.token = token
        # Set up headers with authentication for GitHub API
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CloudIAM-Scraper"
        }
        self.base_url = "https://api.github.com"
        self.policies_dir = "policies"
        # Create policies directory if it doesn't exist
        os.makedirs(self.policies_dir, exist_ok=True)
        
        # Get highest policy number from existing files
        self.count = self.get_next_policy_number()
        self.errors = 0
        self.duplicates = 0
        
        # Load hashes of existing policies to prevent duplicates
        self.existing_hashes = self.load_existing_hashes()

    def get_next_policy_number(self) -> int:
        """
        Find the next available policy number by checking existing files.
        This allows running scraper multiple times without overwriting.
        
        Returns:
            int: Next available policy number
        """
        existing_policies = [f for f in os.listdir(self.policies_dir) 
                            if f.startswith('real_policy_') and f.endswith('.json')]
        
        if not existing_policies:
            return 0
        
        # Extract numbers and find the maximum
        numbers = []
        for policy in existing_policies:
            try:
                # Extract number from real_policy_N.json
                num = int(policy.replace('real_policy_', '').replace('.json', ''))
                numbers.append(num)
            except ValueError:
                continue
        
        if numbers:
            return max(numbers) + 1
        return 0

    def load_existing_hashes(self) -> Set[str]:
        """
        Load hashes of all existing policies to detect duplicates.
        
        Returns:
            Set[str]: Set of existing policy hashes
        """
        hashes = set()
        
        for filename in os.listdir(self.policies_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.policies_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        # Hash the policy content to detect duplicates
                        file_hash = hashlib.md5(content.encode()).hexdigest()
                        hashes.add(file_hash)
                except Exception as e:
                    print(f"   Warning: Could not hash {filename}: {str(e)}")
        
        return hashes

    def get_policy_hash(self, policy_dict: Dict) -> str:
        """
        Calculate hash of a policy to detect duplicates.
        
        Args:
            policy_dict (Dict): Policy JSON object
            
        Returns:
            str: MD5 hash of the policy
        """
        # Convert to JSON string and hash it
        policy_str = json.dumps(policy_dict, sort_keys=True)
        return hashlib.md5(policy_str.encode()).hexdigest()

    def search_policies(self, queries: List[str]) -> List[Dict]:
        """
        Search GitHub for IAM policy files using multiple search queries.
        
        Args:
            queries (List[str]): List of search queries to execute
            
        Returns:
            List[Dict]: List of file items found on GitHub
        """
        results = []
        
        for query in queries:
            print(f"\nSearching GitHub: {query}")
            url = f"{self.base_url}/search/code"
            params = {
                "q": query,
                "per_page": 100,  # Maximum results per page
                "sort": "stars",  # Sort by popularity
                "order": "desc"
            }
            
            try:
                # Check internet before making request
                if not check_internet_connection():
                    return results
                
                # Make API request to GitHub
                response = requests.get(url, headers=self.headers, params=params, timeout=10)
                
                if response.status_code == 200:
                    # Successfully retrieved results
                    data = response.json()
                    items = data.get('items', [])
                    print(f"   Found {len(items)} files")
                    results.extend(items)
                elif response.status_code == 403:
                    # Rate limit exceeded
                    print(f"   WARNING: API rate limited. Waiting before retry...")
                    time.sleep(5)
                else:
                    # Other error occurred
                    print(f"   ERROR: HTTP {response.status_code}")
            except Exception as e:
                # Network or request error
                print(f"   ERROR: {str(e)}")
        
        return results

    def download_policy(self, item: Dict) -> bool:
        """
        Download a single policy file from GitHub and save locally.
        Skips duplicates.
        
        Args:
            item (Dict): GitHub search result item with file information
            
        Returns:
            bool: True if successfully saved, False otherwise
        """
        # Check internet before downloading
        if not check_internet_connection():
            self.errors += 1
            return False
        
        try:
            # Convert GitHub web URL to raw content URL
            raw_url = item['html_url'].replace(
                'github.com', 'raw.githubusercontent.com'
            ).replace('/blob', '')
            
            # Download the raw file content
            response = requests.get(raw_url, headers=self.headers, timeout=5)
            
            if response.status_code == 200:
                # Try to parse as JSON to validate it's a real policy
                try:
                    policy = json.loads(response.text)
                    
                    # Check if it contains IAM policy structure
                    if 'Statement' in policy or 'Version' in policy:
                        # Check for duplicates
                        policy_hash = self.get_policy_hash(policy)
                        
                        if policy_hash in self.existing_hashes:
                            # This policy already exists
                            self.duplicates += 1
                            return False
                        
                        # Save valid, unique policy to local directory
                        filename = f"{self.policies_dir}/real_policy_{self.count}.json"
                        with open(filename, 'w') as f:
                            json.dump(policy, f, indent=2)
                        
                        # Add to existing hashes
                        self.existing_hashes.add(policy_hash)
                        
                        print(f"   Saved: {filename}")
                        self.count += 1
                        return True
                except json.JSONDecodeError:
                    # File is not valid JSON, skip it
                    pass
        except Exception as e:
            # Error downloading or processing file
            self.errors += 1
        
        return False

    def scrape(self, queries: List[str], max_policies: int = 500):
        """
        Main scraping function that orchestrates the entire process.
        Can be run multiple times to collect more policies.
        
        Args:
            queries (List[str]): Search queries to use
            max_policies (int): Target number of policies to collect
        """
        print("=" * 60)
        print("GitHub IAM Policy Scraper (Anti-Duplicate)")
        print("=" * 60)
        print(f"Target: {max_policies} policies")
        print(f"Currently have: {self.count} policies")
        print(f"Remaining to collect: {max_policies - self.count}\n")
        
        # Step 1: Search for policy files on GitHub
        items = self.search_policies(queries)
        
        print(f"\nTotal items found: {len(items)}")
        print("Downloading policies...\n")
        
        # Step 2: Download each policy file
        policies_added_this_round = 0
        for i, item in enumerate(items):
            # Stop if we've reached target
            if self.count >= max_policies:
                print(f"\nTarget of {max_policies} policies reached!")
                break
            
            # Show progress
            print(f"[{i+1}/{len(items)}] {item['name']} from {item['repository']['full_name']}")
            if self.download_policy(item):
                policies_added_this_round += 1
            
            # Rate limiting - small delay between requests to respect API limits
            time.sleep(0.1)
        
        # Step 3: Print summary
        print("\n" + "=" * 60)
        print("SCRAPING COMPLETE")
        print(f"   Total policies saved: {self.count}")
        print(f"   Added this round: {policies_added_this_round}")
        print(f"   Duplicates skipped: {self.duplicates}")
        print(f"   Errors: {self.errors}")
        print(f"   Location: {self.policies_dir}/")
        
        if self.count >= max_policies:
            print(f"\n   SUCCESS: Reached target of {max_policies} policies!")
        else:
            print(f"\n   Need {max_policies - self.count} more policies to reach target")
            print(f"   Run this script again to collect more!")
        print("=" * 60)


def main():
    """
    Main entry point. Load configuration and start scraping.
    Can run multiple rounds to collect more policies without duplicates.
    """
    # Load GitHub token from configuration file
    config_file = "/home/vboxuser/cloud-iam-capstone/config/.env.local"
    
    if not os.path.exists(config_file):
        print(f"ERROR: {config_file} not found!")
        print("Create it with your GitHub token:")
        print(f"   mkdir -p ../config")
        print(f"   echo 'GITHUB_TOKEN=your_token' > {config_file}")
        return
    
    # Read and parse token from config file
    try:
        with open(config_file, 'r') as f:
            content = f.read().strip()
        
        # Handle different format possibilities
        if '=' in content:
            # Format: GITHUB_TOKEN=ghp_xxxxx
            token = content.split('=', 1)[1].strip()
        else:
            # Token is the entire content
            token = content.strip()
        
        # Validate token exists and is not placeholder
        if not token or token == 'your_token_here':
            print("ERROR: No valid token found in config/.env.local")
            print("Update the file with your actual GitHub token")
            return
        
        print(f"Token loaded successfully\n")
        
    except Exception as e:
        print(f"ERROR reading config file: {str(e)}")
        return
    
    # SET NUMBER OF ROUNDS HERE - Change this number to run more/fewer rounds
    num_rounds = 5
    target_policies = 500
    
    # Print header for multi-round scraping
    print("=" * 60)
    print(f"MULTI-ROUND SCRAPING: {num_rounds} rounds")
    print(f"Target: {target_policies} policies")
    print("=" * 60 + "\n")
    
    # Define search queries for finding IAM policies
    queries = [
        "filename:iam.json",
        "filename:policy.json",
        "path:iam language:json Statement",
        "filename:aws-policy.json",
        "AWS policy json",
        "IAM policy github",
    ]
    
    # Track statistics across all rounds
    total_added = 0
    total_duplicates = 0
    total_errors = 0
    
    # Run multiple rounds
    for round_num in range(1, num_rounds + 1):
        print(f"\n{'='*60}")
        print(f"ROUND {round_num} of {num_rounds}")
        print(f"{'='*60}\n")
        
        # Create scraper instance for this round
        scraper = GitHubPolicyScraper(token)
        
        # Get current count before scraping
        before_count = scraper.count
        
        # Run scraper
        scraper.scrape(queries, max_policies=target_policies)
        
        # Track statistics
        policies_added = scraper.count - before_count
        total_added += policies_added
        total_duplicates += scraper.duplicates
        total_errors += scraper.errors
        
        # Check if target reached
        if scraper.count >= target_policies:
            print(f"\nTarget reached! Stopping early.")
            break
        
        # Wait between rounds to avoid rate limiting
        if round_num < num_rounds and scraper.count < target_policies:
            print(f"\nWaiting 10 seconds before next round...")
            time.sleep(10)
    
    # Final summary across all rounds
    print("\n" + "=" * 60)
    print("ALL ROUNDS COMPLETE")
    print("=" * 60)
    print(f"Total rounds executed: {round_num}")
    print(f"Total policies collected: {scraper.count}")
    print(f"Total added this session: {total_added}")
    print(f"Total duplicates skipped: {total_duplicates}")
    print(f"Total errors: {total_errors}")
    print(f"Target: {target_policies}")
    
    if scraper.count >= target_policies:
        print(f"\nSUCCESS: Reached target of {target_policies} policies!")
    else:
        remaining = target_policies - scraper.count
        print(f"\nNeed {remaining} more policies to reach {target_policies}")
        print(f"Run this script again or increase num_rounds")
    print("=" * 60)


if __name__ == "__main__":
    main()
