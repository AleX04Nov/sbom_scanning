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


ASSETS_REPO_SEM = asyncio.Semaphore(30)
DOWNLOAD_SEM = asyncio.Semaphore(30)
RATE_LIMIT_LOCK = asyncio.Lock()
ANNOUNCE_RATE_LIMIT_LOCK = asyncio.Lock()

MIN_TIMEOUT = 2
MAX_TIMEOUT = 10

session: aiohttp.ClientSession = None
github_api: gidgethub.aiohttp.GitHubAPI = None
data_folder = ''
sbom_files_folder = ''
sbom_archive_folder = ''
rate_limit_hit = False
rate_limit_reset = 0
gh_token = ''

ARCHIVE_EXTENSIONS = [".zip", ".tar", ".tgz", ".7z", ".rar", ".gz", ".xz"]

downloaded_sbom_info = {}
fully_downloaded_repos_count = 0

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


async def download_sbom_from_gh_release(author: str, repo: str, asset: dict, repo_sbom_list: list) -> None:
    url = asset['url']
    asset_name = url.split('/')[-1]
    asset_name_ext = '.' + asset_name.split('.')[-1]
    if asset_name_ext in ARCHIVE_EXTENSIONS:
        # download archive
        archive_name = f"{author}_{repo}_release_{utils.random_string(8)}_{asset_name}"
        archive_filepath = os.path.join(sbom_archive_folder, archive_name)

        status_code = await download_gh_file(url, archive_filepath)
        if status_code == 200:
            # extract archive
            # generate unpacked folder name
            unpacked_folder = os.path.join(sbom_archive_folder, f"{author}_{repo}_release_{asset_name}_{utils.random_string(8)}")

            # create unpacked folder
            os.mkdir(unpacked_folder)

            # extract archive
            if not await utils.unpack_archive(archive_filepath, unpacked_folder):
                print(f"Failed to extract {archive_name}")
                if os.path.exists(archive_filepath):
                    os.remove(archive_filepath)
                return
            unpacked_folder_contents = os.listdir(unpacked_folder)
            archive_basepath = unpacked_folder
            archive_basepath2 = os.path.join(unpacked_folder, unpacked_folder_contents[0])

            for sbom in asset['sboms']:
                if not os.path.exists(os.path.join(archive_basepath, sbom['path'])):
                    archive_basepath = archive_basepath2

                # get sbom name
                sbom_name = sbom['path'].split('/')[-1]
                sbom_name = sbom_name.split('\\')[-1]

                # create sbom_downloaded_filepath
                sbom_downloaded_name = f"{author}_{repo}_release_{utils.random_string(8)}_{sbom_name}"
                sbom_downloaded_filepath = os.path.join(sbom_files_folder, sbom_downloaded_name)

                # copy sbom file from archive to sbom_files_folder with sbom_downloaded_filepath
                sbom_file_path = os.path.join(archive_basepath, sbom['path'])
                if os.path.exists(sbom_file_path):
                    # copy sbom file
                    os.rename(sbom_file_path, sbom_downloaded_filepath)
                    repo_sbom_list.append({
                        'path': sbom['path'],
                        'type': sbom['type'],
                        'url': url,
                        'file_name': sbom_downloaded_name
                    })
                else:
                    print(f"Failed to download {url}")
                    print(f"Status code: {status_code}")
                    if os.path.exists(sbom_downloaded_filepath):
                        os.remove(sbom_downloaded_filepath)
            # remove archive
            if os.path.exists(archive_filepath):
                os.remove(archive_filepath)
            if os.path.exists(unpacked_folder):
                await aioshutil.rmtree(unpacked_folder)
        else:
            print(f"Failed to download {url}")
            print(f"Status code: {status_code}")
            if os.path.exists(archive_filepath):
                os.remove(archive_filepath)
            return
    else:
        for sbom in asset['sboms']:
            # get sbom name
            sbom_name = sbom['path'].split('/')[-1]

            # create sbom_downloaded_filepath
            sbom_downloaded_name = f"{author}_{repo}_release_{utils.random_string(8)}_{sbom_name}"
            sbom_downloaded_filepath = os.path.join(sbom_files_folder, sbom_downloaded_name)

            # download sbom file
            status_code = await download_gh_file(url, sbom_downloaded_filepath)
            if status_code == 200:
                repo_sbom_list.append({
                    'path': sbom['path'],
                    'type': sbom['type'],
                    'url': url,
                    'file_name': sbom_downloaded_name
                })
            else:
                print(f"Failed to download {sbom['url']}")
                print(f"Status code: {status_code}")
                if os.path.exists(sbom_downloaded_filepath):
                    os.remove(sbom_downloaded_filepath)
    return


async def download_sbom_from_gh_src(author: str, repo: str, asset: dict, repo_sbom_list: list) -> None:
    for sbom in asset['sboms']:
        # get sbom name
        sbom_name = sbom['path'].split('/')[-1]

        # create sbom_downloaded_filepath with random string at the end
        sbom_downloaded_name = f"{author}_{repo}_{asset['sha']}_{utils.random_string(8)}_{sbom_name}"
        sbom_downloaded_filepath = os.path.join(sbom_files_folder, sbom_downloaded_name)

        # create url
        url = f"https://raw.githubusercontent.com/{author}/{repo}/{asset['sha']}/{sbom['path']}"

        # download sbom file
        status_code = await download_gh_file(url, sbom_downloaded_filepath)
        if status_code == 200:
            repo_sbom_list.append({
                'path': sbom['path'],
                'type': sbom['type'],
                'url': url,
                'file_name': sbom_downloaded_name
            })
        else:
            print(f"Failed to download {url}")
            print(f"Status code: {status_code}")
            if os.path.exists(sbom_downloaded_filepath):
                os.remove(sbom_downloaded_filepath)
    return


async def download_sbom_from_asset(author: str, repo: str, asset: dict, repo_sbom_list: list) -> None:
    global fully_downloaded_repos_count

    # claim semaphore
    async with ASSETS_REPO_SEM:
        if asset.get('sha'):
            await download_sbom_from_gh_src(author, repo, asset, repo_sbom_list)
        elif asset['url'].find('/artifact/') != -1:
            # if url contains 'artifact' in it, download from artifacts
            #await download_sbom_from_gh_artifact(author, repo, asset, repo_sbom_list)
            # pass because there are no artifacts in the sbom_list.json
            pass
        else:
            await download_sbom_from_gh_release(author, repo, asset, repo_sbom_list)
    fully_downloaded_repos_count += 1
    if fully_downloaded_repos_count % 100 == 0:
        print(f"Fully downloaded {fully_downloaded_repos_count} assets")
    return

async def download_sbom_files_all(sbom_list: dict) -> dict:
    global downloaded_sbom_list
    downloaded_sbom_list = {}

    # asyncio gather list of tasks
    tasks = []

    for author in sbom_list:
        downloaded_sbom_list[author] = {}
        for repo in sbom_list[author]:
            repo_sbom_list = []
            downloaded_sbom_list[author][repo] = repo_sbom_list
            for asset in sbom_list[author][repo]['assets']:
                tasks.append(download_sbom_from_asset(author, repo, asset, repo_sbom_list))

    await asyncio.gather(*tasks)
    return downloaded_sbom_list



async def main(folder='', github_token=''):
    global session, data_folder, github_api, gh_token, sbom_files_folder, sbom_archive_folder

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    sbom_files_folder = os.path.join(data_folder, f'sbom_files')
    sbom_archive_folder = os.path.join(data_folder, f'sbom_archives')
    if not os.path.exists(sbom_files_folder):
        os.mkdir(sbom_files_folder)
    if not os.path.exists(sbom_archive_folder):
        os.mkdir(sbom_archive_folder)

    if github_token == '':
        with open('github_token.txt', 'r') as f:
            github_token = f.readline().strip()
    gh_token = github_token

    # read 'sbom_list.json' file
    # if there is 'sbom_list_with_may.json' file, use it instead
    if os.path.exists(os.path.join(data_folder, 'sbom_list_with_may.json')):
        with open(os.path.join(data_folder, 'sbom_list_with_may.json'), 'r') as f:
            sbom_list = json.load(f)
    else:
        with open(os.path.join(data_folder, 'sbom_list.json'), 'r') as f:
            sbom_list = json.load(f)

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

    downloaded_sbom_list = await download_sbom_files_all(sbom_list)

    # remove empty repos
    for author in list(downloaded_sbom_list.keys()):
        for repo in list(downloaded_sbom_list[author].keys()):
            if len(downloaded_sbom_list[author][repo]) == 0:
                del downloaded_sbom_list[author][repo]
        if len(downloaded_sbom_list[author]) == 0:
            del downloaded_sbom_list[author]

    # save assets_info to file
    with open(os.path.join(data_folder, 'downloaded_sbom_list.json'), 'w') as f:
        json.dump(downloaded_sbom_list, f, indent=4)

    await session.close()
    return


if __name__ == "__main__":
    asyncio.run(main())