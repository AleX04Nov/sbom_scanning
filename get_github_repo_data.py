import asyncio
import os
import random
import time

import aiohttp
import gidgethub.aiohttp
import json

import utils

REPO_SEM = asyncio.Semaphore(20)
REQUEST_SEM = asyncio.Semaphore(80)
RATE_LIMIT_LOCK = asyncio.Lock()
ANNOUNCE_RATE_LIMIT_LOCK = asyncio.Lock()

MIN_TIMEOUT = 2
MAX_TIMEOUT = 10

session: aiohttp.ClientSession = None
github_api: gidgethub.aiohttp.GitHubAPI = None
data_folder = ''
rate_limit_hit = False
rate_limit_reset = 0
repos_to_check_count = 0
checked_repos_count = 0
repo_info = {}
dump_folder = ''


def dump_repo_info(dump_filename="repos_info_dump.json"):
    global repo_info, data_folder, dump_folder

    # check if the dump folder exists
    if not os.path.exists(os.path.join(data_folder, dump_folder)):
        os.mkdir(os.path.join(data_folder, dump_folder))

    # dump the info about the repos to a json file
    with open(os.path.join(data_folder, dump_folder, dump_filename), 'w') as f:
        json.dump(repo_info, f, indent=4)
    return

async def get_rate_limit() -> dict:
    global rate_limit_reset, rate_limit_hit

    async with RATE_LIMIT_LOCK:
        rate_limit = await github_api.getitem('/rate_limit')
        if rate_limit['rate']['remaining'] < 10:
            rate_limit_hit = True
        else:
            rate_limit_hit = False
        rate_limit_reset = rate_limit['rate']['reset']
    return rate_limit


async def send_gh_request(url: str) -> dict:
    global rate_limit_hit

    while True:
        async with REQUEST_SEM:
            if rate_limit_hit:
                await asyncio.sleep(rate_limit_reset - int(time.time()) + 1)
                async with ANNOUNCE_RATE_LIMIT_LOCK:
                    if rate_limit_hit:
                        rate_limit = await get_rate_limit()
                        print(f"GitHub API rate limit: {rate_limit['rate']['remaining']} remaining")
                time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                await asyncio.sleep(time_to_sleep)
            try:
                time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                await asyncio.sleep(time_to_sleep)
                response = await github_api.getitem(url)
                return response
            except gidgethub.BadRequest as e:
                if 'API rate limit exceeded for user ID' in e.args[0]:
                    async with ANNOUNCE_RATE_LIMIT_LOCK:
                        if not rate_limit_hit:
                            rate_limit = await get_rate_limit()
                            print(f"GitHub API rate limit: {rate_limit['rate']['remaining']} remaining")
                            if rate_limit['rate']['remaining'] < 10:
                                print("GitHub API rate limit exceeded")
                                print(f"Remaining: {rate_limit['rate']['remaining']}")
                                print(f"Time to reset: {rate_limit['rate']['reset']} ({rate_limit_reset - int(time.time()) + 1} seconds)")
                                print("Waiting for reset...")
                elif 'Not Found' in e.args[0]:
                    return {}
                elif 'Repository access blocked' in e.args[0]:
                    return {}
                else:
                    print(f"Error: {e.args[0]}")
                time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                await asyncio.sleep(time_to_sleep)
                continue
            except Exception as e:
                print(f"Error: {e}")
                time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                await asyncio.sleep(time_to_sleep)
                continue


# get the default branch, latest release, source code archive, and artifacts
# get the assets that are smaller than 100 MB
# and only one asset that is bigger than 100 MB (the biggest asset)
async def get_info(author, repo, repo_object) -> None:
    global checked_repos_count

    ASSETS_THRESHOLD_FILESIZE = 100 * 1024 * 1024 # 100 MB

    repo_object['releases'] = []
    repo_object['artifacts'] = []
    repo_object['sourcecode_archive'] = ''
    repo_object['default_branch'] = ''

    async with REPO_SEM:
        get_default_branch_gh_url = f'/repos/{author}/{repo}'
        latest_release_gh_url = f'/repos/{author}/{repo}/releases?per_page={1}'
        sourcecode_archive_gh_url = f'/repos/{author}/{repo}/tarball'
        artifacts_gh_url = f'/repos/{author}/{repo}/actions/artifacts?per_page={100}'

        repo_overall_info = await send_gh_request(get_default_branch_gh_url)
        if repo_overall_info == {}:
            print(f"Repository access blocked. Repository: {author}/{repo}")
            repo_object = {}
            return
        repo_object['default_branch'] = repo_overall_info['default_branch']
        sourcecode_archive_gh_url += f"/{repo_object['default_branch']}"
        repo_object['sourcecode_archive'] = sourcecode_archive_gh_url

        releases = await send_gh_request(latest_release_gh_url)
        if len(releases) != 0:
            assets_to_download = []
            assets = releases[0]['assets']
            the_biggest_threshold_asset = {}
            for asset in assets:
                if asset['name'].endswith(".sbom") \
                    or asset['name'].endswith(".spdx") \
                        or asset['name'].endswith(".json") \
                        or asset['name'].endswith(".xml") \
                        or asset['name'].endswith(".yaml") \
                        or asset['name'].endswith(".yml") \
                        or asset['name'].endswith(".rdf") \
                        or asset['name'].endswith(".bom") \
                        or asset['name'].endswith(".txt") \
                        or asset['name'].endswith(".tar") \
                        or asset['name'].endswith(".tgz") \
                        or asset['name'].endswith(".zip") \
                        or asset['name'].endswith(".7z") \
                        or asset['name'].endswith(".rar") \
                        or asset['name'].endswith(".gz") \
                        or asset['name'].endswith(".xz"):
                    if asset['size'] < ASSETS_THRESHOLD_FILESIZE:
                        assets_to_download.append({'download_url': asset['browser_download_url'], 'size': asset['size']})
                    if asset['size'] > the_biggest_threshold_asset.get('size', 0) and asset['size'] > ASSETS_THRESHOLD_FILESIZE:
                        the_biggest_threshold_asset = asset
            if the_biggest_threshold_asset != {}:
                assets_to_download.append(
                    {
                        'download_url': the_biggest_threshold_asset['browser_download_url'],
                        'size': the_biggest_threshold_asset['size']
                    }
                )
            repo_object['releases'] = assets_to_download
        else:
            repo_object['releases'] = []

        artifacts = await send_gh_request(artifacts_gh_url)
        if artifacts.get("total_count", 0) != 0:
            artifacts_to_download = []
            latest_artifact_commit_sha = ''
            the_biggest_artifact = {}
            for artifact in artifacts['artifacts']:
                # we need to do those checks, because enountered with this error:
                #     if artifact['workflow_run']['head_branch'] != repo_object['default_branch']:
                # TypeError: 'NoneType' object is not subscriptable
                # and we dont know in what variable the None is stored
                if artifact is None:
                    continue
                if artifact.get('workflow_run', None) is None:
                    continue
                if repo_object is None:
                    continue
                if artifact.get('workflow_run').get('head_branch', -1) != repo_object['default_branch']:
                    continue
                if artifact['expired']:
                    continue
                if latest_artifact_commit_sha == '':
                    latest_artifact_commit_sha = artifact['workflow_run']['head_sha']
                elif latest_artifact_commit_sha != artifact['workflow_run']['head_sha']:
                    continue
                if artifact['size_in_bytes'] < ASSETS_THRESHOLD_FILESIZE:
                    artifacts_to_download.append(
                        {'download_url': artifact['archive_download_url'], 'size': artifact['size_in_bytes']}
                    )
                elif artifact['size_in_bytes'] > the_biggest_artifact.get('size_in_bytes', 0) and artifact['size_in_bytes'] > ASSETS_THRESHOLD_FILESIZE:
                    the_biggest_artifact = artifact
            if the_biggest_artifact != {}:
                artifacts_to_download.append(
                    {
                        'download_url': the_biggest_artifact['archive_download_url'],
                        'size': the_biggest_artifact['size_in_bytes']
                    }
                )
            repo_object['artifacts'] = artifacts_to_download
        else:
            repo_object['artifacts'] = []

        checked_repos_count += 1
        if checked_repos_count % 100 == 0:
            print(f"Checked {checked_repos_count}/{repos_to_check_count} repositories")
            dump_repo_info(f"repos_info_dump_{checked_repos_count}.json")

    return



async def get_info_all(repos_to_check: list[str]) -> dict:
    global repo_info, data_folder, dump_folder, checked_repos_count
    # asyncio gather list of tasks
    tasks = []
    repo_info = {}

    # Find the latest dump file in the dump_folder
    dump_path = os.path.join(data_folder, dump_folder)
    if os.path.exists(dump_path) and os.path.isdir(dump_path):
        print(f"Looking for latest repository information in: {dump_path}")
        
        # Find all files matching the dump pattern
        dump_files = []
        for filename in os.listdir(dump_path):
            if filename.startswith("repos_info_dump_") and filename.endswith(".json"):
                try:
                    # Extract the number part from filename
                    count_str = filename.replace("repos_info_dump_", "").replace(".json", "")
                    count = int(count_str)
                    dump_files.append((count, filename))
                except ValueError:
                    continue

        num_repos = 0
        # Sort by count (descending) and get the latest
        if dump_files:
            dump_files.sort(reverse=True)
            latest_count, latest_filename = dump_files[0]
            latest_dump_path = os.path.join(dump_path, latest_filename)
            
            print(f"Found latest dump file: {latest_filename} with count {latest_count}")
            
            # Load the data from this file
            try:
                with open(latest_dump_path, 'r') as f:
                    repo_info = json.load(f)
                    
                    # Update checked_repos_count to continue from where we left off
                    checked_repos_count = latest_count
                    print(f"Loaded repository info from dump file. Continuing from repo count: {checked_repos_count}")

                    for author in repo_info:
                        for repo in repo_info[author]:
                            # Check if the repository is in the repos_to_check list
                            num_repos += 1
                    
            except Exception as e:
                print(f"Error loading dump file {latest_dump_path}: {str(e)}")
                # Reset repo_info if loading failed
                repo_info = {}
    
    processed_repos = 0
    skipped_repos = 0
    # Process repositories that weren't found in the dump file
    for repo_link in repos_to_check:
        processed_repos += 1

        # remove the "https://" from the beginning of the repo name
        repo_link = repo_link[8:] if repo_link.startswith("https://") else repo_link
        # get the author and repo name
        author, repo_name = repo_link.split('/')[1:]
        
        # init the repo_info dict for repositories not in dump files
        if author not in repo_info:
            repo_info[author] = {}
        # Skip if this repository was already processed
        if repo_info[author].get(repo_name, None) is not None:
            skipped_repos += 1
            continue 
        repo_info[author][repo_name] = {}
        
        # Add task to process this repository
        tasks.append(get_info(author, repo_name, repo_info[author][repo_name]))

    print("Processed repos ", processed_repos)
    print("Skipped repos ", skipped_repos)

    await asyncio.gather(*tasks, return_exceptions=False)

    for author in list(repo_info):
        for repo in list(repo_info[author]):
            if repo_info[author][repo] == {}:
                del repo_info[author][repo]
        if repo_info[author] == {}:
            del repo_info[author]
    return repo_info


async def main(folder='', github_token='') -> dict:
    global session, github_api, data_folder, repos_to_check_count, dump_folder

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder
    # dump folder name contains current timestamp
    dump_folder = f"repos_info_dump_{int(time.time())}"

    if github_token == '':
        with open('github_token.txt', 'r') as f:
            github_token = f.readline().strip()

    repos_to_check = []
    '''
    # read top1k repos
    filename = 'top1k_repos'
    filename = os.path.join(data_folder, 'popular_repos', filename)
    # open and read json data from file
    with open(filename, 'r') as f:
        top1k_repos = json.load(f)
    for repo in top1k_repos:
        # remove the "https://" from the beginning of the repo name
        repos_to_check.append(repo[8:] if repo.startswith("https://") else repo)
    '''

    # read repos from sourcegraph_init_repos
    filename = 'sourcegraph_init_repos'
    filename = os.path.join(data_folder, filename)
    # open and read json data from file
    with open(filename, 'r') as f:
        sourcegraph_init_repos = json.load(f)
    repos_to_check.extend(sourcegraph_init_repos)
    repos_to_check = list(set(repos_to_check))

    '''
    # read repos from may 2023 run (previous SG configuration)
    filename = 'may_2023_repos'
    filename = os.path.join(data_folder, filename)
    # open and read json data from file
    with open(filename, 'r') as f:
        sourcegraph_init_repos = json.load(f)
    repos_to_check.extend(sourcegraph_init_repos)
    repos_to_check = list(set(repos_to_check))
    '''

    # sort the repos
    repos_to_check.sort()
    repos_to_check_count = len(repos_to_check)
    print(f"Repos to check: {repos_to_check_count}")

    # init the session and github api
    session = aiohttp.ClientSession()
    github_api = gidgethub.aiohttp.GitHubAPI(session, "gidgethub", oauth_token=github_token)
    rate_limit = await get_rate_limit()
    print(f"GitHub API rate limit: {rate_limit['rate']['remaining']} remaining")
    if rate_limit['rate']['remaining'] < 10:
        print("GitHub API rate limit exceeded")
        print(f"Remaining: {rate_limit['rate']['remaining']}")
        print(f"Time to reset: {rate_limit['rate']['reset']} ({rate_limit_reset - int(time.time()) + 1} seconds)")
        print("Waiting for reset...")

    # check all repos that are left
    repos_info = await get_info_all(repos_to_check)

    # remove duplicate entries in repos_info
    for author in repos_info:
        for repo in repos_info[author]:
            # detect duplicate entries in repos['author']['repo']['releases']
            # based on the "download_url" value
            releases = repos_info[author][repo]['releases']
            unique_releases = []
            unique_releases_urls = []
            for release in releases:
                if release['download_url'] not in unique_releases_urls:
                    unique_releases.append(release)
                    unique_releases_urls.append(release['download_url'])
            repos_info[author][repo]['releases'] = unique_releases

            # detect duplicate entries in repos['author']['repo']['artifacts']
            # based on the "download_url" value
            artifacts = repos_info[author][repo]['artifacts']
            unique_artifacts = []
            unique_artifacts_urls = []
            for artifact in artifacts:
                if artifact['download_url'] not in unique_artifacts_urls:
                    unique_artifacts.append(artifact)
                    unique_artifacts_urls.append(artifact['download_url'])
            repos_info[author][repo]['artifacts'] = unique_artifacts

    # dump the info about the repos to a json file
    with open(os.path.join(data_folder, 'repos_info.json'), 'w') as f:
        json.dump(repos_info, f, indent=4)

    await session.close()
    return repos_info


if __name__ == '__main__':
    asyncio.run(main())
