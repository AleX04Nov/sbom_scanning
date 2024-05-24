import asyncio
import json
import os
import random
import datetime

import aiohttp
import gidgethub.aiohttp

import utils

REPO_SEM = asyncio.Semaphore(30)
session: aiohttp.ClientSession = None
github_api: gidgethub.aiohttp.GitHubAPI = None
data_folder = ''


async def find_all_commits_for_path(author, repo, path, file) -> list:
    additional_commits = []
    page = 0
    while True:
        page += 1
        async with REPO_SEM:
            try:
                commits = await github_api.getitem(f'/repos/{author}/{repo}/commits?path={path}&per_page={100}&page={page}')
            except gidgethub.BadRequest as e:
                if 'API rate limit exceeded for user ID' in e.args[0]:
                    return []
                elif 'Not Found' in e.args[0]:
                    break
                page -= 1
                time_to_sleep = random.uniform(0.5, 3.3)
                await asyncio.sleep(time_to_sleep)
                continue
        for commit in commits:
            date = datetime.datetime.strptime(commit['commit']['author']['date'], "%Y-%m-%dT%H:%M:%SZ")
            additional_commits.append({
                'sha': commit['sha'],
                'date': int(date.timestamp()),
            })
        if len(commits) < 100:
            break
    file['other_commits'] = additional_commits
    return additional_commits


async def find_all_commits_for_path_all(sboms_by_author) -> bool:
    # asyncio gather list of tasks
    tasks = []
    for author in sboms_by_author:
        for repo in sboms_by_author[author]:
            if repo[:11] != "github.com/":
                continue
            repo_name = repo.split("/")[-1]
            for file in sboms_by_author[author][repo]:
                tasks.append(find_all_commits_for_path(author, repo_name, file['path'], file))
                # other_commits = await find_all_commits_for_path(author, repo.split("/")[-1], file['path'], file)
                # if other_commits == []:
                #    print(f"Rate limit exceeded for your token")
                #    break
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return True


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
    # rate_limit = await github_api.getitem('/rate_limit')

    # open the frozen file
    filename = 'all_sboms_by_author.json'
    filename = os.path.join(data_folder, filename)
    with open(filename, 'r') as f:
        sboms_by_author = json.load(f)

    await find_all_commits_for_path_all(sboms_by_author)

    # dump the sboms_by_author
    with open(os.path.join(data_folder, 'all_commits_by_author.json'), 'w') as f:
        json.dump(sboms_by_author, f, indent=4)

    # close the session
    await session.close()


if __name__ == '__main__':
    asyncio.run(main())
