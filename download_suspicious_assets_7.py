import asyncio
import json
import os
import aioshutil

import aiofiles as aiof

import aiohttp

import utils

REPO_SEM = asyncio.Semaphore(30)
DOWNLOAD_SEM = asyncio.Semaphore(30)
session: aiohttp.ClientSession = None
data_folder = ''

ARCHIVE_EXTENSIONS = [".zip", ".tar", ".tgz", ".7z", ".rar", ".gz", ".xz"]


async def download_assets(assets_url):
    releases_urls = assets_url['releases_to_check']
    assets_url['files_to_check'] = []
    files_to_check = assets_url['files_to_check']
    async with REPO_SEM:
        for release_url in releases_urls:
            author = release_url.split('/')[3]
            repo = release_url.split('/')[4]
            filename = release_url.split('/')[-1]
            async with DOWNLOAD_SEM:
                print(f"Downloading {release_url}")
                while True:
                    try:
                        async with session.get(release_url, timeout=None) as response:
                            # create directory if not exists
                            if not os.path.exists(os.path.join(data_folder, f"assets/{author}/{repo}")):
                                os.makedirs(os.path.join(data_folder, f"assets/{author}/{repo}"))
                            async with aiof.open(os.path.join(data_folder, f"assets/{author}/{repo}/{filename}"), 'wb') as f:
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
                # use shutil.unpack_archive() to extract archive
                try:
                    await aioshutil.unpack_archive(
                        os.path.join(data_folder, f"assets/{author}/{repo}/{filename}"),
                        os.path.join(data_folder, f"assets/{author}/{repo}/{foldername}")
                    )
                except Exception as e:
                    print(f"Error: {e}")
                files_to_check.append(os.path.join(data_folder, f"assets/{author}/{repo}/{foldername}"))
            else:
                files_to_check.append(os.path.join(data_folder, f"assets/{author}/{repo}/{filename}"))


async def download_assets_all(assets_to_download):
    for author in assets_to_download:
        for repo in assets_to_download[author]:
            if repo[:11] != "github.com/":
                continue
            await download_assets(assets_to_download[author][repo])
    print("All assets downloaded")


async def main(folder=''):
    global session, data_folder

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    session = aiohttp.ClientSession()
    # read 'releases_to_check.json' file
    with open(os.path.join(data_folder, 'releases_to_check.json'), 'r') as f:
        releases_to_check = json.load(f)

    await download_assets_all(releases_to_check)

    with open(os.path.join(data_folder, 'assets_to_check.json'), 'w') as f:
        json.dump(releases_to_check, f, indent=4)
    await session.close()


if __name__ == '__main__':
    asyncio.run(main())
