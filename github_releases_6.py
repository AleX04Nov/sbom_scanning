import asyncio
import os
import random

import aiohttp
import gidgethub.aiohttp
import json

import utils

REPO_SEM = asyncio.Semaphore(30)
session: aiohttp.ClientSession = None
github_api: gidgethub.aiohttp.GitHubAPI = None
data_folder = ''


async def get_releases(author, repo, repo_object):
    while True:
        async with REPO_SEM:
            try:
                releases = await github_api.getitem(f'/repos/{author}/{repo}/releases?per_page={1}')
                break
            except gidgethub.BadRequest as e:
                if 'API rate limit exceeded for user ID' in e.args[0]:
                    return []
                elif 'Not Found' in e.args[0]:
                    return []
                time_to_sleep = random.uniform(0.5, 3.3)
                await asyncio.sleep(time_to_sleep)
                continue

    assets_to_download = []
    if len(releases) == 0:
        return assets_to_download
    assets = releases[0]['assets']
    the_biggest_10mb_asset = None
    the_biggest_10mb_asset_size = 0
    for asset in assets:
        if asset['name'].endswith(".sbom") \
            or asset['name'].endswith(".spdx") \
                or asset['name'].endswith(".json") \
                or asset['name'].endswith(".xml") \
                or asset['name'].endswith(".yaml") \
                or asset['name'].endswith(".yml") \
                or asset['name'].endswith(".bom") \
                or asset['name'].endswith(".txt") \
                or asset['name'].endswith(".tar") \
                or asset['name'].endswith(".tgz") \
                or asset['name'].endswith(".zip") \
                or asset['name'].endswith(".7z") \
                or asset['name'].endswith(".rar") \
                or asset['name'].endswith(".gz") \
                or asset['name'].endswith(".xz"):
            if asset['size'] < 10 * 1024 * 1024:
                assets_to_download.append(asset['browser_download_url'])
            if asset['size'] > the_biggest_10mb_asset_size:
                the_biggest_10mb_asset = asset
                the_biggest_10mb_asset_size = asset['size']
    if the_biggest_10mb_asset is not None:
        assets_to_download.append(the_biggest_10mb_asset['browser_download_url'])
    if assets_to_download:
        # remove duplicates
        assets_to_download = list(set(assets_to_download))
        repo_object['releases_to_check'] = assets_to_download
    return assets_to_download


async def get_releases_all(sboms_by_author) -> dict:
    # asyncio gather list of tasks
    tasks = []
    new_sboms_by_author = {}
    for author in sboms_by_author:
        new_sboms_by_author[author] = {}
        for repo in sboms_by_author[author]:
            if repo[:11] != "github.com/":
                continue
            repo_name = repo.split("/")[-1]
            new_sboms_by_author[author][repo] = {}
            tasks.append(get_releases(author, repo_name, new_sboms_by_author[author][repo]))
    await asyncio.gather(*tasks, return_exceptions=False)
    for author in list(new_sboms_by_author):
        for repo in list(new_sboms_by_author[author]):
            if new_sboms_by_author[author][repo] == {}:
                del new_sboms_by_author[author][repo]
        if new_sboms_by_author[author] == {}:
            del new_sboms_by_author[author]

    return new_sboms_by_author


async def main(folder=''):
    global session, github_api, data_folder

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    with open('github_token.txt', 'r') as f:
        github_token = f.readline().strip()
    session = aiohttp.ClientSession()
    github_api = gidgethub.aiohttp.GitHubAPI(session, "gidgethub", oauth_token=github_token)
    # rate_limit = await github_api.getitem('/rate_limit')

    # open all_sboms_by_author.json
    filename = 'all_sboms_by_author.json'
    filename = os.path.join(data_folder, filename)
    with open(filename, 'r') as f:
        sboms_by_author = json.load(f)

    # remove non-github repos
    for author in list(sboms_by_author):
        for repo in list(sboms_by_author[author]):
            if repo[:11] != "github.com/":
                del sboms_by_author[author][repo]
        if sboms_by_author[author] == {}:
            del sboms_by_author[author]
    releases_to_check = await get_releases_all(sboms_by_author)

    # dump the sboms_by_author
    with open(os.path.join(data_folder, 'releases_to_check.json'), 'w') as f:
        json.dump(releases_to_check, f, indent=4)

    await session.close()


if __name__ == '__main__':
    asyncio.run(main())
