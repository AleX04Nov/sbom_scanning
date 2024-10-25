import asyncio
import json
import random
import time
import os

import aioshutil
import aiofiles as aiof
import aiohttp
import gidgethub.aiohttp

import utils
from search_inside_asset import main as search_inside_asset_main

DOWNLOADED_ASSET_FILE_LOCK = asyncio.Lock()
DOWNLOADED_ASSET_FILE_NAME = 'downloaded_assets.txt'

SOURCECODE_REPO_SEM = asyncio.Semaphore(30)
ASSETS_REPO_SEM = asyncio.Semaphore(30)
DOWNLOAD_SEM = asyncio.Semaphore(30)
REQUEST_SEM = asyncio.Semaphore(30)
RATE_LIMIT_LOCK = asyncio.Lock()
ANNOUNCE_RATE_LIMIT_LOCK = asyncio.Lock()

MIN_TIMEOUT = 2
MAX_TIMEOUT = 10

session: aiohttp.ClientSession = None
github_api: gidgethub.aiohttp.GitHubAPI = None
data_folder = ''
dump_folder = ''
rate_limit_hit = False
rate_limit_reset = 0
gh_token = ''

ARCHIVE_EXTENSIONS = [".zip", ".tar", ".tgz", ".7z", ".rar", ".gz", ".xz"]

assets_info = {}

failed_soucecode_repos = []
checked_sourcecode_repos = []
failed_asset_links = []
checked_assets_repos = []
full_checked_repos = []


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


async def download_gh_file(url: str, filepath: str) -> int:
    conn_refused_count = 0
    async with DOWNLOAD_SEM:
        while True:
            if conn_refused_count > 30:
                print(f"Connection refused error count exceeded 15 times. Stopping download {url}")
                return 0
            try:
                time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                await asyncio.sleep(time_to_sleep)
                async with session.get(url, timeout=None, headers={
                    'Accept': 'application/vnd.github.v3.raw',
                    'Authorization': f'Bearer {gh_token}',
                    'X-GitHub-Api-Version': '2022-11-28'
                }) as response:
                    async with aiof.open(filepath, 'wb') as f:
                        await f.write(await response.read())
                        await f.flush()
                        return response.status
            except asyncio.TimeoutError as e:
                print(f"Timeout error while downloading {url}")
                # check if the file exists and remove it
                if os.path.exists(filepath):
                    os.remove(filepath)
                continue
            except ConnectionRefusedError as e:
                conn_refused_count += 1
                # check if the file exists and remove it
                if os.path.exists(filepath):
                    os.remove(filepath)
                continue
            except Exception as e:
                print(f"Error: {e}")
                return 0


def add_failed_sourcecode_repo(repo_url: str):
    global failed_soucecode_repos
    print(f"Failed to download source code from {repo_url}")
    failed_soucecode_repos.append(repo_url)
    with open(os.path.join(dump_folder, 'failed_sourcecode_repos.json'), 'w') as f:
        json.dump(failed_soucecode_repos, f, indent=4)


def add_checked_sourcecode_repo(repo_url: str):
    global checked_sourcecode_repos
    checked_sourcecode_repos.append(repo_url)
    with open(os.path.join(dump_folder, 'checked_sourcecode_repos.json'), 'w') as f:
        json.dump(checked_sourcecode_repos, f, indent=4)
    if repo_url in checked_assets_repos:
        add_full_checked_repo(repo_url)


def add_failed_asset(asset_url: str):
    global failed_asset_links
    failed_asset_links.append(asset_url)
    with open(os.path.join(dump_folder, 'failed_assets.json'), 'w') as f:
        json.dump(failed_asset_links, f, indent=4)


def add_checked_assets_repo(repo_url: str):
    global checked_assets_repos
    checked_assets_repos.append(repo_url)
    with open(os.path.join(dump_folder, 'checked_assets_repos.json'), 'w') as f:
        json.dump(checked_assets_repos, f, indent=4)
    if repo_url in checked_sourcecode_repos:
        add_full_checked_repo(repo_url)


def add_full_checked_repo(repo_url: str):
    global full_checked_repos
    full_checked_repos.append(repo_url)
    with open(os.path.join(dump_folder, 'full_checked_repos.json'), 'w') as f:
        json.dump(full_checked_repos, f, indent=4)

    if len(full_checked_repos) % 100 == 0:
        print(f"Checked {len(full_checked_repos)} repos")
        # make dump of assets_info
        with open(os.path.join(dump_folder, f'assets_info_{len(full_checked_repos)}.json'), 'w') as f:
            json.dump(assets_info, f, indent=4)


async def download_and_check_sourcecode_repo(author, repo, repo_info, assets_info):
    if assets_info.get('assets') is None:
        assets_info['assets'] = []
    sourcecode_info = {}
    assets_info['assets'].append(sourcecode_info)

    async with SOURCECODE_REPO_SEM:
        # download source code archive
        repo_code_url = repo_info['sourcecode_archive']

        # get default branch
        if repo_info.get('default_branch'):
            default_branch: str = repo_info['default_branch']
        else:
            default_branch: str = repo_code_url[repo_code_url.find('tarball/') + 8:]
        # get latest commit hash
        get_latest_commit_info_url = f"/repos/{author}/{repo}/commits/{default_branch}?per_page=1"
        latest_commit_info = await send_gh_request(get_latest_commit_info_url)
        latest_commit_hash = latest_commit_info['sha']
        sourcecode_info['sha'] = latest_commit_hash
        sourcecode_info['branch'] = default_branch
        sourcecode_info['url'] = repo_code_url
        sourcecode_info['sboms'] = []

        # download source code archive
        # prepare folder for source code
        if not os.path.exists(os.path.join(data_folder, 'sourcecode')):
            os.makedirs(os.path.join(data_folder, 'sourcecode'))
        # create filename for source code archive
        sourcecode_archive_filename = f"{author}_{repo}_{default_branch.replace('/', '-')}_{latest_commit_hash}.tar.gz"
        # get full path for source code archive
        sourcecode_archive_path = os.path.join(data_folder, "sourcecode", sourcecode_archive_filename)
        # download source code archive
        sourcecode_full_url = f"https://api.github.com{repo_code_url}"
        # if download failed skip checking
        status_code = await download_gh_file(sourcecode_full_url, sourcecode_archive_path)
        if status_code != 200:
            add_failed_sourcecode_repo(f"github.com/{author}/{repo}")
            print(f"Failed to download source code from {sourcecode_full_url}. Status code: {status_code}")
            # check if the source code archive is already downloaded
            if os.path.exists(sourcecode_archive_path):
                os.remove(sourcecode_archive_path)
            return
        # check archive with asset SBOM detector
        res_bool, detected_sboms = await search_inside_asset_main(data_folder, sourcecode_archive_path, sourcecode_archive_filename)
        if res_bool:
            sourcecode_info['sboms'].extend(detected_sboms)
        else:
            add_failed_sourcecode_repo(f"github.com/{author}/{repo}")

        # remove source code archive
        # check if the sourcecode archive exists
        if os.path.exists(sourcecode_archive_path):
            os.remove(sourcecode_archive_path)

        # add to checked sourcecode repos
        add_checked_sourcecode_repo(f"github.com/{author}/{repo}")
    return


async def download_and_check_assets_repo(author, repo, repo_info, assets_info):
    global checked_sourcecode_repos, failed_soucecode_repos

    if assets_info.get('assets') is None:
        assets_info['assets'] = []

    # check if assets folder exists
    if not os.path.exists(os.path.join(data_folder, 'assets')):
        os.makedirs(os.path.join(data_folder, 'assets'))

    async with ASSETS_REPO_SEM:
        # download assets
        # begin with artifacts
        if repo_info.get('artifacts'):
            for artifact in repo_info['artifacts']:
                # init artifact info
                artifact_info = {}
                assets_info['assets'].append(artifact_info)

                artifact_info['url'] = artifact['download_url']
                artifact_info['sboms'] = []

                # download artifact
                artifact_url = artifact['download_url']
                artifact_id = artifact_url.split('/')[-2]
                artifact_extension = artifact_url.split('/')[-1]
                artifact_filename = f"{author}_{repo}_artifact_{artifact_id}.{artifact_extension}"
                artifact_path = os.path.join(data_folder, 'assets', artifact_filename)
                status_code = await download_gh_file(artifact_url, artifact_path)
                if status_code == 410:
                    add_failed_asset(artifact_url)
                    # check if the artifact archive is already downloaded
                    if os.path.exists(artifact_path):
                        os.remove(artifact_path)
                    continue
                if status_code != 200:
                    print(f"Failed to download artifact from {artifact_url}. Status code: {status_code}")
                    add_failed_asset(artifact_url)
                    # check if the artifact archive is already downloaded
                    if os.path.exists(artifact_path):
                        os.remove(artifact_path)
                    continue

                # check artifact with asset SBOM detector
                res_bool, detected_sboms = await search_inside_asset_main(data_folder, artifact_path, artifact_filename)
                if res_bool:
                    artifact['sboms'] = detected_sboms
                else:
                    add_failed_asset(artifact_url)

                # remove artifact
                # check if the artifact archive exists
                if os.path.exists(artifact_path):
                    os.remove(artifact_path)

        # then check releases
        if repo_info.get('releases'):
            if len(repo_info['releases']):
                # create folder for releases
                releases_folder = os.path.join(data_folder, 'assets', f"{author}_{repo}_releases")
                if not os.path.exists(releases_folder):
                    os.makedirs(releases_folder)

            for release_file in repo_info['releases']:
                # init release info
                release_info = {}
                assets_info['assets'].append(release_info)

                release_info['url'] = release_file['download_url']
                release_info['sboms'] = []

                # download release
                release_url = release_file['download_url']
                release_id = release_url.split('/')[-2]
                release_extension = release_url.split('/')[-1]
                release_filename = f"{author}_{repo}_release_{release_id}.{release_extension}"
                release_path = os.path.join(data_folder, releases_folder, release_filename)
                status_code = await download_gh_file(release_url, release_path)
                if status_code != 200:
                    print(f"Failed to download asset from {release_url}. Status code: {status_code}")
                    add_failed_asset(release_url)
                    # check if the release archive is already downloaded
                    if os.path.exists(release_path):
                        os.remove(release_path)
                    continue

                # check release with asset SBOM detector
                res_bool, detected_sboms = await search_inside_asset_main(data_folder, release_path, release_filename)
                if res_bool:
                    release_info['sboms'] = detected_sboms
                else:
                    add_failed_asset(release_url)

                # remove release
                # check if the release archive exists
                if os.path.exists(release_path):
                    os.remove(release_path)

            # remove releases folder
            if len(repo_info['releases']):
                await aioshutil.rmtree(releases_folder)

        # add to checked assets repos
        add_checked_assets_repo(f"github.com/{author}/{repo}")
    return


async def download_and_check_assets_all(repo_info):
    global assets_info
    assets_info = {}

    # asyncio gather list of tasks
    tasks = []

    for author in repo_info:
        assets_info[author] = {}
        for repo in repo_info[author]:
            assets_info[author][repo] = {}
            tasks.append(download_and_check_sourcecode_repo(author, repo, repo_info[author][repo], assets_info[author][repo]))
            tasks.append(download_and_check_assets_repo(author, repo, repo_info[author][repo], assets_info[author][repo]))

    await asyncio.gather(*tasks)
    return assets_info


async def main(folder='', github_token=''):
    global session, data_folder, github_api, gh_token, dump_folder

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    dump_folder = os.path.join(data_folder, f'download_and_check_dump_{int(time.time())}')
    os.mkdir(dump_folder)

    if github_token == '':
        with open('github_token.txt', 'r') as f:
            github_token = f.readline().strip()
    gh_token = github_token

    # read 'repos_info.json' file
    with open(os.path.join(data_folder, 'repos_info.json'), 'r') as f:
        repos_info = json.load(f)

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

    assets_info = await download_and_check_assets_all(repos_info)

    # save assets_info to file
    with open(os.path.join(data_folder, 'assets_info.json'), 'w') as f:
        json.dump(assets_info, f, indent=4)

    await session.close()
    return


if __name__ == '__main__':
    asyncio.run(main())
