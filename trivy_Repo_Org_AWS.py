import os
import boto3
import json
import subprocess
import requests

# Function to retrieve the GitHub PAT token from AWS Secrets Manager
def get_github_token_from_secrets_manager(secret_name, region_name):
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # Fetch the secret value from AWS Secrets Manager
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except Exception as e:
        print("Error fetching secret from AWS Secrets Manager:", e)
        return None
    else:
        secret_value_dict = json.loads(get_secret_value_response['SecretString'])
        github_pat = secret_value_dict.get(secret_name, "")
        return github_pat

# Function to perform Trivy scan on a repository
def trivy_scan(repo_url, repo_name):
    os.system(f"git clone {repo_url}")

    os.system(f"trivy repo {repo_url}")

    # # current_directory = os.getcwd()
    # print("Current Directory:", current_directory)

    subprocess.run(["trivy", "filesystem", "--format", "cyclonedx", "-o", f"trivy_sbom_{repo_name}.json", os.path.join(os.getcwd(), repo_name)])

    subprocess.run(["trivy","sbom",f"trivy_sbom_{repo_name}.json","-o",f"trivy_sbom_vulnerabilities_{repo_name}.json","--format","json"])



    with open(f"trivy_sbom_vulnerabilities_{repo_name}.json", "r") as json_file:
        data = json.load(json_file)

    # Check if 'Results' key exists in the JSON data
    if 'Results' in data:
        # Process vulnerability data if 'Results' key exists
        vulnerabilities = data['Results']
        for vulnerability in vulnerabilities:
            if 'Vulnerabilities' in vulnerability:
                for vuln in vulnerability['Vulnerabilities']:
                    # Add repository name to vulnerability information
                    vuln['Repository'] = vulnerability.get("Repository", repo_name)
    else:
        # If 'Results' key is not found, set repository name to repo_name
        data['Results'] = [{"Repository": repo_name, "Vulnerabilities": []}]

    # Write the modified JSON data back to the file
    with open(f"trivy_sbom_vulnerabilities_{repo_name}.json", "w") as json_file:
        json.dump(data, json_file, indent=4)




# Function to retrieve repositories under a GitHub organization
def get_organization_repositories(organization_name, github_pat):
    headers = {
        "Authorization": f"token {github_pat}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"https://api.github.com/orgs/{organization_name}/repos"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        repos = response.json()
        return [repo["clone_url"] for repo in repos]
    else:
        print(f"Failed to fetch repositories: {response.status_code}")
        return []

# Function to handle input and initiate Trivy scan
def initiate_trivy_scan():
    choice = input("Enter '1' to provide GitHub organization name or '2' to provide repo URL: ")
    
    if choice == '1':
        organization_name = input("Enter the GitHub organization name: ") # Value: Software-Supply
        secret_name = input("Enter the name of your secret in AWS Secrets Manager: ") # Value: MY_GITHUB_PAT
        region_name = input("Enter your AWS region: ") # Input value: us-east-1
        github_pat = get_github_token_from_secrets_manager(secret_name, region_name) 
        if not github_pat:
            print("Error: GitHub token not found in AWS Secrets Manager.")
            exit()

        repo_urls = get_organization_repositories(organization_name, github_pat)
        if not repo_urls:
            print("No repositories found.")
            exit()

        for repo_url in repo_urls:
            repo_name = repo_url.split('/')[-1].split('.')[0] # Fetch the GitHub repo name
            trivy_scan(repo_url, repo_name)
            
    elif choice == '2':
        repo_url = input("Enter the GitHub repository URL: ")
        secret_name = input("Enter the name of your secret in AWS Secrets Manager: ")    # Value: MY_GITHUB_PAT
        region_name = input("Enter your AWS region: ") # Input value: us-east-1
        github_pat = get_github_token_from_secrets_manager(secret_name, region_name) 
        if not github_pat:
            print("Error: GitHub token not found in AWS Secrets Manager.")
            exit()
            
        repo_name = repo_url.split('/')[-1].split('.')[0] # Fetch the GitHub repo name
        trivy_scan(repo_url, repo_name)
        
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    initiate_trivy_scan()
