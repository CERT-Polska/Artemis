import re
import requests

dockerfile_path = "docker/Dockerfile"

def get_latest_version(repo):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()['tag_name']
    except requests.RequestException as e:
        print(f"Error fetching latest version for {repo}: {e}")
        return None

def update_dockerfile(package, new_version, pattern, replacement):
    print(f"Attempting to update {package} to {new_version}")
    try:
        with open(dockerfile_path, 'r') as file:
            content = file.read()

        match = re.search(pattern, content, re.DOTALL)
        if match:
            current_version = match.group(2)
            print(f"Current version of {package}: {current_version}")
            if current_version == new_version:
                print(f"{package} is already up to date ({current_version})")
                return False

            new_content = re.sub(pattern, replacement.format(new_version), content)
            print(f"Updating {package} from {current_version} to {new_version}")

            with open(dockerfile_path, 'w') as file:
                file.write(new_content)
            print(f"Successfully updated {package} to {new_version}")
            return True
        else:
            print(f"Could not find a match for {package} in the Dockerfile")
            return False
    except IOError as e:
        print(f"Error accessing the Dockerfile: {e}")
        return False

def update_package_in_dockerfile(package, pattern, replacement):
    owner, repo = package.split('/')[:2]  
    latest_version = get_latest_version(f"{owner}/{repo}")
    if latest_version:
        update_dockerfile(package, latest_version, pattern, replacement)
    else:
        print(f"Failed to get latest version for {package}")


# packages = [
#     "projectdiscovery/naabu",
#     "praetorian-inc/fingerprintx", 
#     "lc/gau",
#     "projectdiscovery/subfinder"
# ]

# for package in packages:
#     pattern = rf'(GOBIN=/usr/local/bin/ go install github\.com/{package}.*?@)(v[0-9]+\.[0-9]+\.[0-9]+)'
#     replacement = r"\1{}"
#     update_package_in_dockerfile(package, pattern, replacement)

# Update nuclei separately
nuclei_package = "projectdiscovery/nuclei"
pattern = r'(git clone https://github\.com/projectdiscovery/nuclei\.git -b )(v[0-9]+\.[0-9]+\.[0-9]+)'
replacement = r"\1{}"
update_package_in_dockerfile(nuclei_package, pattern, replacement)

print("Script execution completed.")