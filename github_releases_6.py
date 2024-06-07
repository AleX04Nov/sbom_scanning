import asyncio
import os
import random
import time

import aiohttp
import gidgethub.aiohttp
import json

import utils

REPO_SEM = asyncio.Semaphore(8)
session: aiohttp.ClientSession = None
github_api: gidgethub.aiohttp.GitHubAPI = None
data_folder = ''
rate_limit_hit = False


async def get_releases(author, repo, repo_object) -> tuple[str, list | str]:
    global rate_limit_hit

    while True:
        async with REPO_SEM:
            if rate_limit_hit:
                return f"github.com/{author}/{repo}", "API rate limit exceeded"
            try:
                time_to_sleep = random.uniform(0.5, 3.3)
                await asyncio.sleep(time_to_sleep)
                releases = await github_api.getitem(f'/repos/{author}/{repo}/releases?per_page={1}')
                break
            except gidgethub.BadRequest as e:
                if 'API rate limit exceeded for user ID' in e.args[0]:
                    rate_limit_hit = True
                    return f"github.com/{author}/{repo}", "API rate limit exceeded"
                elif 'Not Found' in e.args[0]:
                    return f"github.com/{author}/{repo}", []
                elif 'Repository access blocked' in e.args[0]:
                    return f"github.com/{author}/{repo}", []
                else:
                    print(f"Error: {e.args[0]}")
                time_to_sleep = random.uniform(0.5, 3.3)
                await asyncio.sleep(time_to_sleep)
                continue
            except Exception as e:
                print(f"Error: {e}")
                time_to_sleep = random.uniform(0.5, 3.3)
                await asyncio.sleep(time_to_sleep)
                continue

    assets_to_download = []
    if len(releases) == 0:
        return f"github.com/{author}/{repo}", assets_to_download
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
    return f"github.com/{author}/{repo}", assets_to_download


async def get_releases_all(sboms_by_author) -> tuple[dict, bool]:
    # asyncio gather list of tasks
    tasks = []
    new_sboms_by_author = {}
    releases_already_checked = []

    for author in sboms_by_author:
        new_sboms_by_author[author] = {}
        for repo in sboms_by_author[author]:
            if repo[:11] != "github.com/":
                continue
            repo_name = repo.split("/")[-1]
            new_sboms_by_author[author][repo] = {}
            tasks.append(get_releases(author, repo_name, new_sboms_by_author[author][repo]))
    results = await asyncio.gather(*tasks, return_exceptions=False)
    for author in list(new_sboms_by_author):
        for repo in list(new_sboms_by_author[author]):
            if new_sboms_by_author[author][repo] == {}:
                del new_sboms_by_author[author][repo]
        if new_sboms_by_author[author] == {}:
            del new_sboms_by_author[author]

    for result in results:
        if result[1] == "API rate limit exceeded":
            continue
        releases_already_checked.append(result[0])

    # dump the releases_already_checked
    filename = 'releases_already_checked.txt'
    filename = os.path.join(data_folder, filename)
    with open(filename, 'a') as f:
        for repo_url in releases_already_checked:
            f.write(f"{repo_url}\n")

    return new_sboms_by_author, not rate_limit_hit


async def main(folder='', additional_repos=False):
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
    rate_limit = await github_api.getitem('/rate_limit')
    print(f"GitHub API rate limit: {rate_limit['rate']['remaining']} remaining")
    if rate_limit['rate']['remaining'] < 10:
        print("GitHub API rate limit exceeded")
        print(f"Remaining: {rate_limit['rate']['remaining']}")
        print(f"Time to reset: {rate_limit['rate']['reset']}")
        print("Waiting for reset...")
        await asyncio.sleep(rate_limit['rate']['reset'] - int(time.time()) + 1)

    if additional_repos:
        filename = 'additional_repos.txt'
        filename = os.path.join(data_folder, filename)
        with open(filename, 'r') as f:
            repos_to_check_plain_list = f.readlines()
            repos_to_check_plain_list = [x.strip() for x in repos_to_check_plain_list]
        repos_to_check = {}
        for repo in repos_to_check_plain_list:
            if repo[:11] != "github.com/":
                continue
            repo = repo.replace('https://', '')
            author = repo.split('/')[1]
            if author not in repos_to_check:
                repos_to_check[author] = {}
            repos_to_check[author][repo] = []
    else:
        # open all_sboms_by_author.json
        filename = 'all_sboms_by_author.json'
        filename = os.path.join(data_folder, filename)
        with open(filename, 'r') as f:
            repos_to_check = json.load(f)

    # remove non-github repos
    for author in list(repos_to_check):
        for repo in list(repos_to_check[author]):
            if repo[:11] != "github.com/":
                del repos_to_check[author][repo]
        if repos_to_check[author] == {}:
            del repos_to_check[author]

    # read already scanned repos
    # check if file exists
    already_checked = {}
    if os.path.exists(os.path.join(data_folder, 'releases_to_check.json')):
        with open(os.path.join(data_folder, 'releases_to_check.json'), 'r') as f:
            already_checked = json.load(f)
    if additional_repos:
        if os.path.exists(os.path.join(data_folder, 'all_sboms_by_author.json')):
            with open(os.path.join(data_folder, 'all_sboms_by_author.json'), 'r') as f:
                already_checked.update(json.load(f))
        if os.path.exists(os.path.join(data_folder, 'releases_to_check_additional.json')):
            with open(os.path.join(data_folder, 'releases_to_check_additional.json'), 'r') as f:
                already_checked.update(json.load(f))

    # remove already checked repos
    for author in list(repos_to_check):
        for repo in list(repos_to_check[author]):
            repos_to_check[author][repo] = {}
            if already_checked.get(author) and repo in already_checked[author]:
                del repos_to_check[author][repo]
        if repos_to_check[author] == {}:
            del repos_to_check[author]

    # remove already checked repos
    if os.path.exists(os.path.join(data_folder, 'releases_already_checked.txt')):
        with open(os.path.join(data_folder, 'releases_already_checked.txt'), 'r') as f:
            already_checked_repos = f.readlines()
            already_checked_repos = [x.strip() for x in already_checked_repos]

        # remove already checked repos from `releases_already_checked.txt`
        for author in list(repos_to_check):
            for repo in list(repos_to_check[author]):
                if repo in already_checked_repos:
                    del repos_to_check[author][repo]
            if repos_to_check[author] == {}:
                del repos_to_check[author]

    # check all repos that are left
    releases_to_check, checked_all = await get_releases_all(repos_to_check)

    # dump the sboms_by_author
    already_checked = {}
    if additional_repos:
        if os.path.exists(os.path.join(data_folder, 'releases_to_check_additional.json')):
            with open(os.path.join(data_folder, 'releases_to_check_additional.json'), 'r') as f:
                already_checked = json.load(f)
        with open(os.path.join(data_folder, 'releases_to_check_additional.json'), 'w') as f:
            for author in list(already_checked):
                if author not in releases_to_check:
                    releases_to_check[author] = already_checked[author]
                    continue
                for repo in list(already_checked[author]):
                    if repo not in releases_to_check[author]:
                        releases_to_check[author][repo] = already_checked[author][repo]
                    releases_to_check[author][repo]["releases_to_check"].extend(
                        releases_to_check[author][repo].get("releases_to_check", []))
                    releases_to_check[author][repo]["releases_to_check"] = list(
                        set(releases_to_check[author][repo]["releases_to_check"]))
            for author in list(releases_to_check):
                for repo in list(releases_to_check[author]):
                    if releases_to_check[author][repo] == {}:
                        del releases_to_check[author][repo]
                if releases_to_check[author] == {}:
                    del releases_to_check[author]
            json.dump(releases_to_check, f, indent=4)
    else:
        if os.path.exists(os.path.join(data_folder, 'releases_to_check.json')):
            with open(os.path.join(data_folder, 'releases_to_check.json'), 'r') as f:
                already_checked = json.load(f)
        with open(os.path.join(data_folder, 'releases_to_check.json'), 'w') as f:
            for author in list(already_checked):
                if author not in releases_to_check:
                    releases_to_check[author] = already_checked[author]
                    continue
                for repo in list(already_checked[author]):
                    if repo not in releases_to_check[author]:
                        releases_to_check[author][repo] = already_checked[author][repo]
                        continue
                    if releases_to_check[author][repo].get('releases_to_check', None) is None:
                        releases_to_check[author][repo]['releases_to_check'] = already_checked[author][repo].get(
                            'releases_to_check', [])
                    else:
                        releases_to_check[author][repo]["releases_to_check"].extend(
                            releases_to_check[author][repo].get("releases_to_check",[]))
                    releases_to_check[author][repo]["releases_to_check"] = list(
                        set(releases_to_check[author][repo]["releases_to_check"]))
            for author in list(releases_to_check):
                for repo in list(releases_to_check[author]):
                    if releases_to_check[author][repo] == {}:
                        del releases_to_check[author][repo]
                if releases_to_check[author] == {}:
                    del releases_to_check[author]
            json.dump(releases_to_check, f, indent=4)

    await session.close()

    return releases_to_check, checked_all


if __name__ == '__main__':
    asyncio.run(main())
