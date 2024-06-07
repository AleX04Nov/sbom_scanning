import asyncio
import json
import os
import aioshutil

import aiofiles as aiof

import aiohttp

import utils

DOWNLOADED_ASSET_FILE_LOCK = asyncio.Lock()
DOWNLOADED_ASSET_FILE_NAME = 'downloaded_assets.txt'

REPO_SEM = asyncio.Semaphore(30)
DOWNLOAD_SEM = asyncio.Semaphore(30)

session: aiohttp.ClientSession = None
data_folder = ''

ARCHIVE_EXTENSIONS = [".zip", ".tar", ".tgz", ".7z", ".rar", ".gz", ".xz"]
ASSETS_THRESHOLD_GB = 10

async def add_downloaded_asset(asset_url: str):
    async with DOWNLOADED_ASSET_FILE_LOCK:
        with open(os.path.join(data_folder, DOWNLOADED_ASSET_FILE_NAME), 'a') as f:
            f.write(f"{asset_url}\n")


async def download_assets(author, repo, assets_url, downloaded_assets=set(), additional_repos=False):
    releases_urls = assets_url['releases_to_check']
    assets_url['files_to_check'] = []
    files_to_check = assets_url['files_to_check']
    if additional_repos:
        assets_folder = 'assets_additional'
    else:
        assets_folder = 'assets'
    async with REPO_SEM:
        # get size of folder
        folder_size = utils.get_folder_size(os.path.join(data_folder, assets_folder))
        if folder_size > ASSETS_THRESHOLD_GB * 1024 * 1024 * 1024:
            return "THRESHOLD_REACHED"
        for release_url in releases_urls:
            if release_url in downloaded_assets:
                continue
            filename = release_url.split('/')[-1]
            async with DOWNLOAD_SEM:
                print(f"Downloading {release_url}")
                while True:
                    try:
                        async with session.get(release_url, timeout=None) as response:
                            # create directory if not exists
                            if not os.path.exists(os.path.join(data_folder, f"{assets_folder}/{author}/{repo}")):
                                os.makedirs(os.path.join(data_folder, f"{assets_folder}/{author}/{repo}"))
                            async with aiof.open(os.path.join(data_folder, f"{assets_folder}/{author}/{repo}/{filename}"), 'wb') as f:
                                await f.write(await response.read())
                                await f.flush()
                                break
                    except asyncio.TimeoutError as e:
                        print(f"Timeout error while downloading {release_url}")
                        continue
                    except Exception as e:
                        print(f"Error: {e}")
                        break
            # check if file is archive
            if '.' + filename.split('.')[-1] in ARCHIVE_EXTENSIONS:
                print(f"Extracting {filename} from {repo}")
                foldername = '.'.join(filename.split('.')[:-1])
                while os.path.exists(os.path.join(data_folder, f"{assets_folder}/{author}/{repo}/{foldername}")):
                    foldername = foldername + "_"
                # use shutil.unpack_archive() to extract archive
                try:
                    await aioshutil.unpack_archive(
                        os.path.join(data_folder, f"{assets_folder}/{author}/{repo}/{filename}"),
                        os.path.join(data_folder, f"{assets_folder}/{author}/{repo}/{foldername}")
                    )
                except Exception as e:
                    print(f"Error: {e}")
                files_to_check.append({
                    'url': release_url,
                    'path': f"{author}/{repo}/{foldername}"
                })
            else:
                files_to_check.append({
                    'url': release_url,
                    'path': f"{author}/{repo}/{filename}"
                })
            await add_downloaded_asset(release_url)
    return "OK"


async def download_assets_all(assets_to_download, additional_repos=False):
    # read already downloaded assets
    downloaded_assets = []
    if os.path.exists(os.path.join(data_folder, DOWNLOADED_ASSET_FILE_NAME)):
        with open(os.path.join(data_folder, DOWNLOADED_ASSET_FILE_NAME), 'r') as f:
            downloaded_assets = set(f.read().splitlines())

    for author in assets_to_download:
        for repo in assets_to_download[author]:
            if repo[:11] != "github.com/":
                continue
            res = await download_assets(author, repo.split("/")[-1], assets_to_download[author][repo], downloaded_assets, additional_repos=additional_repos)
            if res == "THRESHOLD_REACHED":
                print("Threshold reached")
                return "THRESHOLD_REACHED"
    print("All assets downloaded")
    return "OK"


async def main(folder='', additional_repos=False):
    global session, data_folder

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    session = aiohttp.ClientSession()
    # read 'releases_to_check.json' file
    if additional_repos:
        if os.path.exists(os.path.join(data_folder, 'releases_to_check_additional.json')):
            with open(os.path.join(data_folder, 'releases_to_check_additional.json'), 'r') as f:
                releases_to_check = json.load(f)
    else:
        if os.path.exists(os.path.join(data_folder, 'releases_to_check.json')):
            with open(os.path.join(data_folder, 'releases_to_check.json'), 'r') as f:
                releases_to_check = json.load(f)

    res = await download_assets_all(releases_to_check, additional_repos=additional_repos)

    # update drop file
    releases_to_check_previous = {}
    if additional_repos:
        if os.path.exists(os.path.join(data_folder, 'assets_to_check_additional.json')):
            with open(os.path.join(data_folder, 'assets_to_check_additional.json'), 'r') as f:
                releases_to_check_previous = json.load(f)
        with open(os.path.join(data_folder, 'assets_to_check_additional.json'), 'w') as f:
            for author in releases_to_check_previous:
                if author not in releases_to_check:
                    releases_to_check[author] = releases_to_check_previous[author]
                    continue
                for repo in releases_to_check_previous[author]:
                    if repo not in releases_to_check[author]:
                        releases_to_check[author][repo] = releases_to_check_previous[author][repo]
                        continue
                    if releases_to_check_previous[author][repo].get('files_to_check') is None:
                        releases_to_check[author][repo]['files_to_check'] = releases_to_check_previous[author][repo]['files_to_check']
                    else:
                        releases_to_check[author][repo]['files_to_check'].extend(releases_to_check_previous[author][repo]['files_to_check'])
                        releases_to_check[author][repo]['files_to_check'] = [i for n, i in enumerate(releases_to_check[author][repo]['files_to_check']) if i not in releases_to_check[author][repo]['files_to_check'][n + 1:]]
            for author in list(releases_to_check):
                for repo in list(releases_to_check[author]):
                    if releases_to_check[author][repo].get('releases_to_check') is not None:
                        del releases_to_check[author][repo]['releases_to_check']
                    if releases_to_check[author][repo].get('files_to_check') is not None and releases_to_check[author][repo]['files_to_check'] == []:
                        del releases_to_check[author][repo]['files_to_check']
                    if releases_to_check[author][repo] == {}:
                        del releases_to_check[author][repo]
                if releases_to_check[author] == {}:
                    del releases_to_check[author]
            json.dump(releases_to_check, f, indent=4)
    else:
        if os.path.exists(os.path.join(data_folder, 'assets_to_check.json')):
            with open(os.path.join(data_folder, 'assets_to_check.json'), 'r') as f:
                releases_to_check_previous = json.load(f)
        with open(os.path.join(data_folder, 'assets_to_check.json'), 'w') as f:
            for author in releases_to_check_previous:
                if author not in releases_to_check:
                    releases_to_check[author] = releases_to_check_previous[author]
                    continue
                for repo in releases_to_check_previous[author]:
                    if repo not in releases_to_check[author]:
                        releases_to_check[author][repo] = releases_to_check_previous[author][repo]
                        continue
                    if releases_to_check_previous[author][repo].get('files_to_check') is None:
                        releases_to_check[author][repo]['files_to_check'] = releases_to_check_previous[author][repo]['files_to_check']
                    else:
                        releases_to_check[author][repo]['files_to_check'].extend(releases_to_check_previous[author][repo]['files_to_check'])
                        releases_to_check[author][repo]['files_to_check'] = [i for n, i in enumerate(releases_to_check[author][repo]['files_to_check']) if i not in releases_to_check[author][repo]['files_to_check'][n + 1:]]
            for author in list(releases_to_check):
                for repo in list(releases_to_check[author]):
                    if releases_to_check[author][repo].get('releases_to_check') is not None:
                        del releases_to_check[author][repo]['releases_to_check']
                    if releases_to_check[author][repo].get('files_to_check') is not None and releases_to_check[author][repo]['files_to_check'] == []:
                        del releases_to_check[author][repo]['files_to_check']
                    if releases_to_check[author][repo] == {}:
                        del releases_to_check[author][repo]
                if releases_to_check[author] == {}:
                    del releases_to_check[author]
            json.dump(releases_to_check, f, indent=4)


    await session.close()
    return res


if __name__ == '__main__':
    asyncio.run(main())
