import os
import json
import subprocess
import requests
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Function to retrieve the GitHub PAT token from Azure Key Vault
def get_github_token_from_key_vault(vault_url, secret_name):
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    try:
        secret = client.get_secret(secret_name)
        return secret.value
    except Exception as e:
        print("Error fetching secret from Azure Key Vault:", e)
        return None

# Function to perform Trivy scan on a repository
def trivy_scan(repo_url, repo_name):
    os.system(f"git clone {repo_url}")

    os.system(f"trivy repo {repo_url}")

    current_directory = os.getcwd()
    print("Current Directory:", current_directory)

    subprocess.run(["trivy", "filesystem", "--format", "cyclonedx", "-o", f"trivy_sbom_{repo_name}.json", os.path.join(os.getcwd(), repo_name)])

    subprocess.run(["trivy","sbom",f"trivy_sbom_{repo_name}.json","-o",f"trivy_sbom_vulnerabilities_{repo_name}.json"])

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
        organization_name = input("Enter the GitHub organization name: ")
        vault_url = input("Enter the URL of your Azure Key Vault: ")
        secret_name = input("Enter the name of your secret in Azure Key Vault: ") 

        github_pat = get_github_token_from_key_vault(vault_url, secret_name) 
        if not github_pat:
            print("Error: GitHub token not found in Azure Key Vault.")
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
        vault_url = input("Enter the URL of your Azure Key Vault: ")
        secret_name = input("Enter the name of your secret in Azure Key Vault: ") 

        github_pat = get_github_token_from_key_vault(vault_url, secret_name) 
        if not github_pat:
            print("Error: GitHub token not found in Azure Key Vault.")
            exit()
            
        repo_name = repo_url.split('/')[-1].split('.')[0] # Fetch the GitHub repo name
        trivy_scan(repo_url, repo_name)
        
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    initiate_trivy_scan()
