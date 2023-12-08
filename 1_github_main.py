import json
import shutil

import git
import os
import docker
import requests
from docker import DockerClient
from github import Github, Repository, Auth
import github


docker_client: DockerClient
github_api: Github


popular_languages = [
    # 'C',
    'C++',
    'C#',
    # 'CoffeeScript',
    # 'Dart',
    'Dockerfile',
    'Go',
    # 'Groovy',
    'Haskell',
    'Java',
    'JavaScript',
    'Kotlin',
    # 'Objective-C',
    # 'Perl',
    # 'PHP',
    'Python',
    'Ruby',
    'Rust',
    # 'Scala',
    # 'Shell',
    # 'Swift',
    # 'TypeScript',
]


def list_rindex(lst, x):
    for r_idx, elt in enumerate(reversed(lst)):
        if elt == x:
            return len(lst) - 1 - r_idx


def is_git_repo(path):
    try:
        _ = git.Repo(path).git_dir
        return True
    except git.exc.InvalidGitRepositoryError as e:
        return False


def detect_sbom_filename(filename: str) -> bool:
    trigger_strings = [
        'sbom',
        'spdx',
        'cyclonedx',
        'cdx',
        'bom',
    ]
    trigger_extensions = [
        '.json',
        '.xml',
        '.yaml',
        '.yml',
        '.sbom',
    ]
    filename_lower = filename.lower()
    return (
            any(trigger in filename_lower for trigger in trigger_strings) and
            any(trigger in filename_lower for trigger in trigger_extensions)
    )


def get_hot_repos():
    query = 'stars:>1'# size:<=30000'
    for lang in popular_languages:
        query += f' language:{lang}'
    repositories = github_api.search_repositories(query=query, sort="stars", order="desc")
    print(repositories.totalCount)
    return repositories


# clone repo if it does not exist and init submodules
# update the repo if it exists and update the submodules
def clone_repo(repository: Repository, root_dir: str) -> str:
    repo_path = f"/{repository.full_name}"
    git_dir_path = root_dir + repo_path
    if os.path.exists(git_dir_path) and is_git_repo(git_dir_path):
        repo = git.Repo(git_dir_path)
        repo.remotes.origin.pull()
    else:
        if os.path.exists(git_dir_path):
            shutil.rmtree(git_dir_path)
        repo = git.Repo.clone_from(repository.html_url, git_dir_path)
    for submodule in repo.submodules:
        try:
            submodule.update(init=True, recursive=True, keep_going=True)
        except git.exc.GitCommandError as e:
            print("Failed to update submodule. Due to this error:")
            print(e)
    return git_dir_path


# get the list of all level2 subdirectories
def get_all_lvl2_dirs(target_dir: str) -> list[str]:
    if (not os.path.exists(target_dir)) or (not os.path.isdir(target_dir)):
        return []
    lvl1 = [os.path.join(target_dir, name) for name in os.listdir(target_dir)
            if os.path.isdir(os.path.join(target_dir, name))]
    return [os.path.join(lvl1_dir, name) for lvl1_dir in lvl1 for name in os.listdir(lvl1_dir)]


def run_osv_scanner_on_git(target_dir: str) -> dict:
    dirs_list = get_all_lvl2_dirs(target_dir)[:10]
    osv_results = {}
    for repo_dir in dirs_list:
        if not is_git_repo(repo_dir):
            continue
        repo = git.Repo(repo_dir)
        repo_author = repo.remotes.origin.url.split('.git')[0].split('/')[-2]
        repo_name = repo.remotes.origin.url.split('.git')[0].split('/')[-1]
        repo_full_name = repo_author + '_' + repo_name
        run_osv_scanner(repo_dir)
        # read json from file and add it to the dict
        with open(os.path.join(repo_dir, 'scan-results.json'), 'r') as json_file:
            try:
                osv_results[repo_full_name] = json.load(json_file)
            except json.decoder.JSONDecodeError:
                osv_results[repo_full_name] = None
    return osv_results


def get_dir_size(dir_path):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(dir_path):
        for file in filenames:
            file_path = os.path.join(dirpath, file)
            if not os.path.islink(file_path):
                total_size += os.path.getsize(file_path)
    return total_size


def get_sbom_from_github(repo_owner: str, repo_name, github_token: str) -> dict | None:
    resp = requests.get(
        f"https://api.github.com/repos/{repo_owner}/{repo_name}/dependency-graph/sbom",
        headers={
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {github_token}',
            'X-GitHub-Api-Version': '2022-11-28'
        }
    )
    if resp.status_code == 200:
        return resp.json()
    return None


def get_sbom_from_github_by_release(repo: Repository, max_files: int = 4) -> dict:
    results = {}
    try:
        latest_release = repo.get_latest_release()
    except github.GithubException as e:
        return results
    curr_file_no = 0
    for asset in latest_release.assets:
        if curr_file_no >= max_files:
            break
        if detect_sbom_filename(asset.name):
            resp = requests.get(
                asset.browser_download_url,
            )
            if resp.status_code == 200:
                results[asset.name] = resp.json()
    return results


def get_sbom_from_github_content(repo: Repository, max_files: int = 4) -> dict:
    results = {}
    curr_file_no = 0
    for content_file in repo.get_contents(""):
        if curr_file_no >= max_files:
            break
        if content_file.type == "dir":
            continue
        if detect_sbom_filename(content_file.name):
            resp = requests.get(
                content_file.download_url,
            )
            if resp.status_code == 200:
                results[content_file.name] = resp.json()
                curr_file_no += 1
    return results


def main():
    global docker_client, github_api
    # init paths
    git_root_dir = os.path.abspath("sbom_storage_dir/git_repos/")

    # init global variables
    docker_client = docker.from_env()
    # read github token from file
    with open('github_token.txt', 'r') as f:
        github_token = f.readline().strip()
    github_auth = Auth.Token(
        github_token
    )
    github_api = Github(auth=github_auth)

    # clear the target directory if it exists
    if os.path.exists(git_root_dir):
        shutil.rmtree(git_root_dir)
    print("Successfully cleared the target directory")

    # get the hot repos
    hot_repos = get_hot_repos()
    print("Successfully got the hot repos")

    # clone them one-by-one onto our machine until we hit free space threshold
    curr_repo_no = 0
    max_repos = 1000
    for repo in hot_repos:
        curr_repo_no += 1
        found_sboms = False

        # print the info
        print(f"{curr_repo_no} / {max_repos} \t {repo.full_name}")

        # get the repo path
        repo_path = os.path.join(git_root_dir, repo.full_name)

        # create the directory if it does not exist
        if not os.path.exists(repo_path):
            os.makedirs(repo_path)

        # get sbom from github insight dependencies
        github_sbom = get_sbom_from_github(repo.owner.login, repo.name, github_auth.token)
        github_sbom = github_sbom['sbom']
        if github_sbom is not None:
            github_sbom_path = os.path.join(repo_path, 'github.sbom.spdx.json')
            with open(github_sbom_path, 'w') as json_file:
                json.dump(github_sbom, json_file, indent=4)

        '''
        # get sbom from github contents
        github_contents_sbom = get_sbom_from_github_content(repo)
        for sbom_name in github_contents_sbom.keys():
            sbom_path = os.path.join(repo_path, sbom_name)
            with open(sbom_path, 'w') as json_file:
                json.dump(github_contents_sbom[sbom_name], json_file, indent=4)

        # get sbom from release page
        github_release_sbom = get_sbom_from_github_by_release(repo)
        for sbom_name in github_release_sbom.keys():
            sbom_path = os.path.join(repo_path, sbom_name)
            with open(sbom_path, 'w') as json_file:
                json.dump(github_release_sbom[sbom_name], json_file, indent=4)
        '''

    print("Successfully got SBOMs from the repos")
    return 0


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
