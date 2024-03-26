# import os
# import boto3
# import json
# import subprocess
# import matplotlib.pyplot as plt


# # The following code is to extract the Github PAT token from AWS secret manager(applicable only for private GITHUB REPO)
# def get_github_token_from_secrets_manager(secret_name, region_name):
#     # Create a Secrets Manager client
#     session = boto3.session.Session()
#     client = session.client(
#         service_name='secretsmanager',
#         region_name=region_name
#     )

#     # Fetch the secret value from AWS Secrets Manager
#     try:
#         get_secret_value_response = client.get_secret_value(
#             SecretId=secret_name
#         )
#     except Exception as e:
#         print("Error fetching secret from AWS Secrets Manager:", e)
#         return None
#     else:
#         secret_value_dict = json.loads(get_secret_value_response['SecretString'])
#         secret_value = secret_value_dict.get("MY_GITHUB_PAT", "")
#         return secret_value

# def trivy_scan(repo_url, repo_type):
#     repo_name = repo_url.split('/')[-1].split('.')[0] # Fetch the Github repo name 
#     # print(repo_name)
#     if repo_type == "private":
#         secret_name = input("Enter the name of your secret in AWS Secrets Manager: ") # Replace with the name of your secret in AWS Secrets Manager(MY_GITHUB_PAT)
#         region_name = input("Enter your AWS region: ")  # Replace with your AWS region(us-east-1)
#         secret_value = get_github_token_from_secrets_manager(secret_name, region_name) # Fetching the value of the secret from the AWS secret manager
#         if not secret_value:
#             print("Error: GitHub token not found in AWS Secrets Manager.")
#             return    
#         os.environ["GITHUB_TOKEN"] = secret_value
            
#     os.system(f"git clone {repo_url}")

#     os.system(f"trivy repo {repo_url}")

#     current_directory = os.getcwd()
#     print("Current Directory:", current_directory)

#     subprocess.run(["trivy", "filesystem", "--format", "cyclonedx", "-o", f"trivy_sbom_{repo_name}.json", os.path.join(os.getcwd(), repo_name)])
    
#     subprocess.run(["trivy","sbom",f"trivy_sbom_{repo_name}.json","-o",f"trivy_sbom_vulnerabilities_{repo_name}.json"])

#     #os.system(f"trivy filesystem --format cyclonedx -o trivy_results_{repo_name}.json {repo_name}")
# if __name__ == "__main__":
#     repo_type = input("Please enter if the repo is public or private: ").lower()
#     github_repo_url = input("Enter the GitHub repo URL: ")
#     trivy_scan(github_repo_url, repo_type)




