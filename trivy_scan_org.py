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
        secret_value = secret_value_dict.get(secret_name, "")
        return secret_value

# Function to perform Trivy scan on a repository
def trivy_scan(repo_url, repo_name):
    os.system(f"git clone {repo_url}")

    os.system(f"trivy repo {repo_url}")

    current_directory = os.getcwd()
    print("Current Directory:", current_directory)

    subprocess.run(["trivy", "filesystem", "--format", "cyclonedx", "-o", f"trivy_sbom_{repo_name}.json", os.path.join(os.getcwd(), repo_name)])

    # research on local filesystem (local directory scanning => saturday evening )

    # $ trivy fs /path/to/project

    
    subprocess.run(["trivy","sbom",f"trivy_sbom_{repo_name}.json","-o",f"trivy_sbom_vulnerabilities_{repo_name}.json"])

    # The following code scans the repository to check for misconfigs in Licenses(shall have pakage-lock.json)

    # subprocess.run(["trivy","fs","--scanners","license","-o",f"trivy_license_{repo_name}",os.path.join(os.getcwd(), repo_name)])

# Function to retrieve all repositories under a GitHub organization
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

if __name__ == "__main__":
    organization_name = input("Enter the GitHub organization name: ")

    secret_name = input("Enter the name of your secret in AWS Secrets Manager: ") 
    region_name = input("Enter your AWS region: ")
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
