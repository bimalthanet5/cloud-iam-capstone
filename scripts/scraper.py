import requests
import json
import os

def scrape_github_policies():
    os.makedirs('policies', exist_ok=True)
    
    queries = [
        'filename:iam.json',
        'filename:policy.json',
    ]
    
    count = 0
    
    for query in queries:
        print(f"Searching: {query}")
        url = f"https://api.github.com/search/code?q={query}&per_page=50"
        
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get('items', [])[:10]:
                    try:
                        raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob', '')
                        file_response = requests.get(raw_url, timeout=5)
                        
                        if file_response.status_code == 200:
                            filename = f"policies/policy_{count}.json"
                            with open(filename, 'w') as f:
                                f.write(file_response.text)
                            count += 1
                            print(f"Saved: {filename}")
                    except:
                        pass
        except:
            pass
    
    print(f"Total: {count} policies")

if __name__ == "__main__":
    scrape_github_policies()
