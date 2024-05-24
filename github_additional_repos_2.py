import json
import os
import random

import asyncio
import aiohttp
import gidgethub.aiohttp

import utils

session: aiohttp.ClientSession = None
github_api: gidgethub.aiohttp.GitHubAPI = None
data_folder = ''


def get_repos_from_sourcegraph(filename: str) -> list:
    # open file and load json data
    with open(filename, 'r') as f:
        sourcegraph_data = json.load(f)
    unique_repos = set()
    for item in sourcegraph_data:
        for result in sourcegraph_data[item]['Results']:
            if result['repository']['name'][:10] == 'github.com':
                unique_repos.add(result['repository']['name'])
            else:
                # print(f"Unknown repository: {result['repository']['name']} in query: {item}")
                pass
    return list(sorted(unique_repos))


def get_repo_author(repo_url: str) -> str:
    return repo_url.split('/')[1]


def get_repo_name(repo_url: str) -> str:
    return repo_url.split('/')[2]


async def find_and_store_additional_repos(author) -> set:
    additional_repos = set()
    page = 0
    while True:
        page += 1
        try:
            repos = await github_api.getitem(f'/users/{author}/repos?per_page={100}&page={page}')
        except gidgethub.BadRequest as e:
            page -= 1
            time_to_sleep = random.uniform(0.5, 3.3)
            await asyncio.sleep(time_to_sleep)
            continue
        for repo in repos:
            if repo['fork']:
                continue
            additional_repos.add(f"github.com/{repo['full_name']}")
        if len(repos) < 100:
            break
    return additional_repos


async def find_and_store_additional_repos_all(repos: list) -> list:
    additional_repos = set()
    unique_authors = set()

    for repo in repos:
        unique_authors.add(get_repo_author(repo))

    # get user repos
    results = await asyncio.gather(*[find_and_store_additional_repos(author) for author in unique_authors], return_exceptions=False)

    for new_repos in results:
        additional_repos.update(new_repos)
    additional_repos = additional_repos - set(repos)
    additional_repos = list(sorted(additional_repos))
    with open(os.path.join(data_folder, 'additional_repos.txt'), 'w') as f:
        for repo in additional_repos:
            f.write(f"{repo}\n")
    return additional_repos


async def main(folder=''):
    global github_api, session, data_folder

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    with open('github_token.txt', 'r') as f:
        github_token = f.readline().strip()

    session = aiohttp.ClientSession()

    github_api = gidgethub.aiohttp.GitHubAPI(session, "gidgethub", oauth_token=github_token)
    unique_repos = get_repos_from_sourcegraph(os.path.join(data_folder, 'sourcegraph_frozen_raw.json'))
    additional_repos = await find_and_store_additional_repos_all(unique_repos)
    print(f"Found {len(additional_repos)} additional repos")

    '''
    additional_repos_by_author = {}
    for repo in additional_repos:
        author = get_repo_author(repo)
        if author not in additional_repos_by_author:
            additional_repos_by_author[author] = {}
        additional_repos_by_author[author][repo] = []
    with open(os.path.join(data_folder, 'additional_repos_by_author.json'), 'w') as f:
        json.dump(additional_repos_by_author, f, indent=4)
    '''

    await session.close()


if __name__ == '__main__':
    asyncio.run(main())
