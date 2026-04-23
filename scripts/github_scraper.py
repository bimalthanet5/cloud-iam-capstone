import requests
import json
import os
import time
from pathlib import Path
from typing import List, Dict

class GitHubPolicyScraper:
    """
    Scraper to collect AWS IAM policies from GitHub repositories.
    Uses GitHub API with authentication token for higher rate limits.
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
        # Track statistics
        self.count = 0
        self.errors = 0

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
        
        Args:
            item (Dict): GitHub search result item with file information
            
        Returns:
            bool: True if successfully saved, False otherwise
        """
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
                        # Save valid policy to local directory
                        filename = f"{self.policies_dir}/real_policy_{self.count}.json"
                        with open(filename, 'w') as f:
                            json.dump(policy, f, indent=2)
                        
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
        
        Args:
            queries (List[str]): Search queries to use
            max_policies (int): Target number of policies to collect
        """
        print("=" * 60)
        print("GitHub IAM Policy Scraper")
        print("=" * 60)
        print(f"Target: {max_policies} policies\n")
        
        # Step 1: Search for policy files on GitHub
        items = self.search_policies(queries)
        
        print(f"\nTotal items found: {len(items)}")
        print("Downloading policies...\n")
        
        # Step 2: Download each policy file
        for i, item in enumerate(items):
            # Stop if we've reached target
            if self.count >= max_policies:
                print(f"\nTarget of {max_policies} policies reached!")
                break
            
            # Show progress
            print(f"[{i+1}/{len(items)}] {item['name']} from {item['repository']['full_name']}")
            self.download_policy(item)
            
            # Rate limiting - small delay between requests to respect API limits
            time.sleep(0.1)
        
        # Step 3: Print summary
        print("\n" + "=" * 60)
        print("SCRAPING COMPLETE")
        print(f"   Policies saved: {self.count}")
        print(f"   Errors: {self.errors}")
        print(f"   Location: {self.policies_dir}/")
        print("=" * 60)


def main():
    """
    Main entry point. Load configuration and start scraping.
    """
    # Load GitHub token from configuration file
    config_file = "../config/.env.local"

    
    if not os.path.exists(config_file):
        print(f"ERROR: {config_file} not found!")
        print("Create it with your GitHub token:")
        print(f"   mkdir -p config")
        print(f"   echo 'GITHUB_TOKEN=your_token' > {config_file}")
        return
    
    # Read token from config file
    with open(config_file) as f:
        token = f.read().strip().split('=')[1]
        
    # Validate token is set
    if not token or token == 'your_token_here':
        print("ERROR: Token not configured! Update config/.env.local with your GitHub token")
        return
    
    # Define search queries for finding IAM policies
    queries = [
        "filename:iam.json",
        "filename:policy.json",
        "path:iam language:json Statement",
        "filename:aws-policy.json",
        "AWS policy json",
        "IAM policy github",
    ]
    
    # Create scraper instance and start scraping
    scraper = GitHubPolicyScraper(token)
    scraper.scrape(queries, max_policies=500)


if __name__ == "__main__":
    main()
