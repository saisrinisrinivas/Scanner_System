import os
import json
import subprocess
import requests
import csv
import boto3
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Function to retrieve the GitHub PAT token from AWS Secrets Manager
def get_github_token_from_aws_secrets_manager(secret_name, region_name):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        secret_value_dict = json.loads(get_secret_value_response['SecretString'])
        github_pat = secret_value_dict.get(secret_name, "")
        return github_pat
    except Exception as e:
        print("Error fetching secret from AWS Secrets Manager:", e)
        return None

# Function to retrieve the GitHub PAT token from Azure Key Vault
def get_github_token_from_azure_key_vault(vault_url, secret_name):
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=vault_url, credential=credential)
    try:
        secret = client.get_secret(secret_name)
        return secret.value
    except Exception as e:
        print("Error fetching secret from Azure Key Vault:", e)
        return None

# Function to perform Trivy scan on a repository
def trivy_scan(repo_url, repo_name, organization_name="", organization_id=""):
    os.system(f"git clone {repo_url}")

    os.system(f"trivy repo {repo_url}")

    subprocess.run(["trivy", "filesystem", "--format", "cyclonedx", "-o", f"trivy_sbom_{repo_name}.json", os.path.join(os.getcwd(), repo_name)])

    subprocess.run(["trivy","sbom",f"trivy_sbom_{repo_name}.json","-o",f"trivy_sbom_vulnerabilities_{repo_name}.json","--format","json"])

    # Adding the Repository URL to SBOM report.
    with open(f"trivy_sbom_{repo_name}.json", "r+") as json_file:
        data = json.load(json_file)

        # Add repository URL to the metadata section
        data["metadata"]["RepositoryURL"] = repo_url

        # Move the file pointer to the beginning of the file
        json_file.seek(0)

        # Write the modified JSON data back to the file
        json.dump(data, json_file, indent=4)
        json_file.truncate()
    

    # Converting the SBOM json file to CSV format.
    with open(f"trivy_sbom_{repo_name}.json") as f:
        data = json.load(f)

    components = data.get('components', [])
    repository_url = data.get('metadata', {}).get('RepositoryURL', '')

    dependency_map = {}

    for dependency in data.get('dependencies', []):
        ref = dependency.get('ref')
        depends_on = dependency.get('dependsOn', [])
        dependency_map[ref] = depends_on


    headers = ["OrganizationName", "OrganizationID", "RepositoryURL", "bom-ref", "type", "group", "name", "version", "purl"]

    if not organization_name and not organization_id:
        organization_name = ""
        organization_id = ""

    # Adding the dependson to sbom.csv
    with open(f"trivy_sbom_{repo_name}.csv", 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        for component in components:
            row = {"OrganizationName": organization_name}  # Adding organization name
            for header in headers[1:]:  # Exclude OrganizationName from headers
                if header == "RepositoryURL":
                    row[header] = repository_url
                else:
                    row[header] = component.get(header, "")
            writer.writerow(row) 

    # Load the dataset again to populate dependsOn column
    dependency_map = {}
    for dependency in data.get('dependencies', []):
        ref = dependency.get('ref')
        depends_on = dependency.get('dependsOn', [])
        dependency_map[ref] = depends_on

    with open(f"trivy_sbom_{repo_name}.csv", 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        rows = list(reader)
    with open(f"trivy_sbom_{repo_name}.csv", 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers + ["dependsOn"])
        writer.writeheader()
        for row in rows:
            bom_ref = row.get("bom-ref")
            row["dependsOn"] = ", ".join(dependency_map.get(bom_ref, []))
            writer.writerow(row)
    print("SBOM_CSV file generated successfully.")

    # Bringing the vulnerabilities report in JSON format
    with open(f"trivy_sbom_vulnerabilities_{repo_name}.json", "r") as json_file:
        data = json.load(json_file)

    # Check if 'Results' key exists in the JSON data
    if 'Results' in data:
        # Process vulnerability data if 'Results' key exists
        vulnerabilities = data['Results']
        for vulnerability in vulnerabilities:
            if 'Vulnerabilities' in vulnerability:
                for vuln in vulnerability['Vulnerabilities']:
                    # Add repository URL to vulnerability information
                    vuln['OrganizationName'] = organization_name
                    vuln['OrganizationID'] = organization_id
                    vuln['RepositoryURL'] = repo_url
    else:
        # If 'Results' key is not found, set repository URL to repo_url
        data['Results'] = [{"RepositoryURL": repo_url, "Vulnerabilities": []}]

    # Write the modified JSON data back to the file
    with open(f"trivy_sbom_vulnerabilities_{repo_name}.json", "w") as json_file:
        json.dump(data, json_file, indent=4)

    # Converting CSV file of SBOM_Vulnerability
    with open(f"trivy_sbom_vulnerabilities_{repo_name}.json", "r") as json_file:
     data = json.load(json_file)

    results = data["Results"][0]["Vulnerabilities"]

    desired_headers_order = ["OrganizationName", "OrganizationID", "RepositoryURL", "VulnerabilityID", "PkgID", "PkgName", "InstalledVersion", 
                             "FixedVersion", "Status", "Severity", "CweIDs", "CVSS", 
                             "PrimaryURL", "References", "PublishedDate", "LastModifiedDate", 
                              "Title", "Description"]

    # Writing to CSV
    with open(f"trivy_sbom_vulnerabilities_{repo_name}.csv", "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=desired_headers_order)
        writer.writeheader()
        for result in results:
            reordered_result = {header: result.get(header, "") for header in desired_headers_order}
            writer.writerow(reordered_result)

    print("Vulnerabilities_CSV file created successfully.")


def get_organization_id(org_name, github_pat):
    headers = {
        "Authorization": f"token {github_pat}",
        "Accept": "application/vnd.github.v3+json"
    }
    url = f"https://api.github.com/orgs/{org_name}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        org_data = response.json()
        organization_id = org_data.get('id', '')
        return organization_id
    else:
        print(f"Failed to fetch organization data: {response.status_code}")
        return None   

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
        organization_id = get_organization_id(organization_name, github_pat)
        return [repo["clone_url"] for repo in repos]
    else:
        print(f"Failed to fetch repositories: {response.status_code}")
        return [], ""

# Function to handle input and initiate Trivy scan
def initiate_trivy_scan():
    secret_source = input("Enter '1' for AWS Secrets Manager or '2' for Azure Key Vault: ")
    if secret_source == '1':
        secret_name = input("Enter the name of your secret in AWS Secrets Manager: ")
        region_name = input("Enter your AWS region: ")
        github_pat = get_github_token_from_aws_secrets_manager(secret_name, region_name) 
    elif secret_source == '2':
        vault_url = input("Enter the URL of your Azure Key Vault: ")
        secret_name = input("Enter the name of your secret in Azure Key Vault: ")
        github_pat = get_github_token_from_azure_key_vault(vault_url, secret_name) 
    else:
        print("Invalid choice.")
        return

    if not github_pat:
        print("Error: GitHub token not found.")
        return

    git_username = input("Enter the Git user name: ")
    os.system(f"git config --global credential.helper store")
    os.system(f"git config --global user.name {git_username}")
    os.system(f"git config --global user.password {github_pat}")

    choice = input("Enter '1' to provide GitHub organization name or '2' to provide repo URL: ")
    if choice == '1':
        organization_name = input("Enter the GitHub organization name: ")
        repo_urls = get_organization_repositories(organization_name, github_pat)
        if not repo_urls:
            print("No repositories found.")
            return

        for repo_url in repo_urls:
            repo_name = repo_url.split('/')[-1].split('.')[0] # Fetch the GitHub repo name
            trivy_scan(repo_url, repo_name)
            
    elif choice == '2':
        repo_url = input("Enter the GitHub repository URL: ")
        repo_name = repo_url.split('/')[-1].split('.')[0] # Fetch the GitHub repo name
        trivy_scan(repo_url, repo_name)
        
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    initiate_trivy_scan()
