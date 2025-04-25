import asyncio
import json
import os
import time

import utils

from github_stars_downloader import main as github_stars_downloader_main
from sourcegraph_1 import main as sourcegraph_main
from get_github_repo_data import main as get_github_repo_data_main
from download_and_check_gh_assets import main as download_and_check_gh_assets_main
from download_sboms import main as download_sbom_files_main
from sbom_external_assessment import main as sbom_external_assessment_main
from sum_up_csv import main as sum_up_csv_main

next_step = ''


# Read the next step in the folder
# If there is no 'next_step' file in the folder,
# create one with the value 'github_stars_init'
def read_next_step(data_folder):
    global next_step
    if not os.path.exists(os.path.join(data_folder, 'next_step.json')):
        # write the first step
        write_next_step(data_folder, 'github_stars_init')
    with open(os.path.join(data_folder, 'next_step.json'), 'r') as f:
        next_step_json = json.load(f)
    next_step = next_step_json['next_step']
    return next_step


def write_next_step(data_folder, next_step_arg):
    global next_step
    with open(os.path.join(data_folder, 'next_step.json'), 'w') as f:
        json.dump({'next_step': next_step_arg}, f)
    next_step = next_step_arg


async def main():
    global next_step
    # get all data folders
    data_folder_path = os.path.abspath(os.getcwd())
    data_folders = utils.get_all_data_folders(data_folder_path)

    # get the latest data folder
    if len(data_folders) > 0:
        data_folder = str(os.path.join(data_folder_path, data_folders[0]))
        # read the next step from the data folder
        next_step = read_next_step(data_folder)

    # if the folder is fully processed, create a new folder
    if next_step == 'done' or len(data_folders) == 0:
        timestamp = str(int(time.time()))
        data_folder = os.path.join(data_folder_path, f'data_{timestamp}')
        os.mkdir(data_folder)

        # init steps in the new folder
        next_step = read_next_step(data_folder)

    # get the github token
    with open("github_token.txt", "r") as f:
        gh_token = f.read().strip()

    popular_languages = list(set(utils.TOP_20_LANGUAGES) | set(utils.GITHUB_POPULAR_LANGUAGES))
    popular_repos_folder = os.path.join(data_folder, 'popular_repos')

    if next_step == 'github_stars_init':
        # get initial frozen set of Top 1000 most star rated github repositories
        # for top-20 languages according to https://www.tiobe.com/tiobe-index/
        for language in popular_languages:
            start_stars = 100
            print(f"Downloading initial SBOM files from Sourcegraph for {language}")
            stars_threshold = 35
            while start_stars >= stars_threshold:
                repos_file = github_stars_downloader_main(
                    data_folder=popular_repos_folder, language=language, gh_token=gh_token, max_size=1048576, start_stars=start_stars
                )
                # read repos from file
                with open(repos_file, 'r') as f:
                    repos = json.load(f)

                # if we have 1000 repos, stop for this language
                if len(repos) >= 1000:
                    break

                # if we have less than 1000 repos, try to get more
                if start_stars > stars_threshold:
                    start_stars = max(start_stars // 2, stars_threshold)
                else:
                    start_stars = 0
            print(f"Successfully got Popular repos ({len(repos)}) for `{language}` .")
        # get all repos into one file
        top1k_repos = []
        for language in popular_languages:
            repos_file = os.path.join(popular_repos_folder, f"top_repos_{language}")
            with open(repos_file, 'r') as f:
                repos = json.load(f)
            # sort tuple by second element from biggest to smallest
            repos.sort(key=lambda x: x[1], reverse=True)
            # leave only top 1000 repos
            if len(repos) > 1000:
                repos = repos[:1000]
            # check the repos on Sourcegraph
            # get the set with only the first element of the tuple
            repos_set = set([repo[0] for repo in repos])
            top1k_repos.extend(repos_set)
        # write top1k repos to file
        with open(os.path.join(popular_repos_folder, 'top1k_repos'), 'w') as f:
            json.dump(top1k_repos, f, indent=4)
        # write the next step
        write_next_step(data_folder, 'sourcegraph_init')
    '''
    if next_step == 'sourcegraph_check_gh_repos':
        # check the repos from the previous step on Sourcegraph
        print("Checking the popular repos on Sourcegraph")
        for language in popular_languages:
            print(f"Checking repos for `{language}`")
            repos_file = os.path.join(popular_repos_folder, f"top_repos_{language}")
            with open(repos_file, 'r') as f:
                repos = json.load(f)
            # sort tuple by second element from biggest to smallest
            repos.sort(key=lambda x: x[1], reverse=True)
            # leave only top 1000 repos
            if len(repos) > 1000:
                repos = repos[:1000]
            # check the repos on Sourcegraph
            # get the set with only the first element of the tuple
            repos_set = set([repo[0] for repo in repos])
            # remove the "https://" from the beginning of the repo name
            repos_set = set([repo[8:] if repo.startswith("https://") else repo for repo in repos_set])
            # check the repos on Sourcegraph
            await sourcegraph_github_popular_repos_main(data_folder, repos_set, language)
        # write the next step
        write_next_step(data_folder, 'sourcegraph_init')
    '''
    if next_step == 'sourcegraph_init':
        print("Downloading initial SBOM files from Sourcegraph")
        await sourcegraph_main(data_folder)
        # get repos from sourcegraph frozen raw
        with open(os.path.join(data_folder, 'sourcegraph_frozen_raw.json'), 'r') as f:
            sbom_dict = json.load(f)
        # get the repos from the sbom_dict
        gh_repos = []
        for query_name in sbom_dict:
            for result in sbom_dict[query_name]['Results']:
                repo_name = result['repository']['name']
                # if repo name starts with 'github.com', add it to the list
                if repo_name.startswith('github.com'):
                    gh_repos.append(repo_name)
        # remove duplicates
        gh_repos = list(set(gh_repos))
        # save the repos to a file
        with open(os.path.join(data_folder, 'sourcegraph_init_repos'), 'w') as f:
            json.dump(gh_repos, f, indent=4)
        write_next_step(data_folder, 'github_get_repo_info')
    if next_step == 'github_get_repo_info':
        print("Getting an information about GitHub repositories")
        await get_github_repo_data_main(data_folder, gh_token)
        write_next_step(data_folder, 'github_download_assets_and_check')
    if next_step == 'github_download_assets_and_check':
        await download_and_check_gh_assets_main(data_folder)
        write_next_step(data_folder, 'assets_to_sbom_list')
    if next_step == 'assets_to_sbom_list':
        with open(os.path.join(data_folder, 'assets_info.json'), 'r') as f:
            assets_info: dict = json.load(f)

        # remove assets without sboms
        for author in list(assets_info.keys()):
            for repo in list(assets_info[author].keys()):
                new_assets = []
                for asset in assets_info[author][repo]['assets']:
                    # if there are no sboms, remove the asset
                    if len(asset.get('sboms', [])) > 0:
                        new_assets.append(asset)
                assets_info[author][repo]['assets'] = new_assets
                # if there are no assets, remove the repo
                if len(assets_info[author][repo]['assets']) == 0:
                    del assets_info[author][repo]
            # if there are no repos, remove the author
            if len(assets_info[author]) == 0:
                del assets_info[author]

        # write the assets_info to a file
        with open(os.path.join(data_folder, 'sbom_list.json'), 'w') as f:
            json.dump(assets_info, f, indent=4)

        # now we need to add the data from the 'res_sbom_list_may.json' file to the assets_info

        # if there is a file with a name: 'res_sbom_list_may.json' add data from it to the assets_info
        if os.path.exists(os.path.join(data_folder, 'res_sbom_list_may.json')):
            with open(os.path.join(data_folder, 'res_sbom_list_may.json'), 'r') as f:
                res_sbom_list_may = json.load(f)
            for author in res_sbom_list_may:
                if author not in assets_info:
                    assets_info[author] = {}
                for repo in res_sbom_list_may[author]:
                    # if repo not begins with github.com skip it
                    if not repo.startswith('github.com'):
                        continue
                    # change repo name to the format 'repo' instead of 'github.com/author/repo'
                    repo_new_format = repo.split('/')[2]
                    if repo_new_format not in assets_info[author]:
                        assets_info[author][repo_new_format] = {}
                    else:
                        # if the repo is already in the assets_info, skip it
                        continue
                    # get unique urls from the assets
                    may_asset_urls: set[str] = set()
                    for asset in res_sbom_list_may[author][repo]:
                        # remove all spdx_spdx assets because we have changed their filter criteria since then
                        if asset['type'] == 'spdx_spdx':
                            continue
                        may_asset_urls.add(asset['url'])
                    # add assets to the assets_info
                    assets_info[author][repo_new_format]['assets'] = []
                    for url in may_asset_urls:
                        new_asset_info = {}
                        # change sourcecode assets info
                        if url.count('/blob/'):
                            sha_hash = url.split('/blob/')[1]
                            sha_hash = sha_hash.split('/')[0]
                            new_asset_info['sha'] = sha_hash
                            new_asset_info['branch'] = ''
                            new_asset_info['url'] = f'/repos/{author}/{repo_new_format}/tarball/'
                        else:
                            new_asset_info['url'] = url
                        new_asset_info['sboms'] = []
                        for asset in res_sbom_list_may[author][repo]:
                            # remove all spdx_spdx assets because we have changed their filter criteria since then
                            if asset['type'] == 'spdx_spdx':
                                continue
                            if asset['url'] == url:
                                new_asset_info['sboms'].append({'type': asset['type'], 'path': asset['path']})
                        assets_info[author][repo_new_format]['assets'].append(new_asset_info)

            # remove assets without sboms
            for author in list(assets_info.keys()):
                for repo in list(assets_info[author].keys()):
                    new_assets = []
                    for asset in assets_info[author][repo]['assets']:
                        # if there are no sboms, remove the asset
                        if len(asset['sboms']) > 0:
                            new_assets.append(asset)
                    assets_info[author][repo]['assets'] = new_assets
                    # if there are no assets, remove the repo
                    if len(assets_info[author][repo]['assets']) == 0:
                        del assets_info[author][repo]
                # if there are no repos, remove the author
                if len(assets_info[author]) == 0:
                    del assets_info[author]

            # write the assets_info to a file
            with open(os.path.join(data_folder, 'sbom_list_with_may.json'), 'w') as f:
                json.dump(assets_info, f, indent=4)
        write_next_step(data_folder, 'download_sbom_files')
    if next_step == 'download_sbom_files':
        await download_sbom_files_main(data_folder, gh_token)
        write_next_step(data_folder, 'sbom_external_assessment')
    if next_step == 'sbom_external_assessment':
        await sbom_external_assessment_main(data_folder)
        write_next_step(data_folder, 'sum_up_csv')
    if next_step == 'sum_up_csv':
        await sum_up_csv_main(data_folder)
        write_next_step(data_folder, 'done')
    if next_step == 'done':
        print("Done")

    return 0


if __name__ == "__main__":
    asyncio.run(main())
