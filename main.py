import asyncio
import json
import os
import time

import utils
from sourcegraph_1 import main as sourcegraph_main
from github_additional_repos_2 import main as github_additional_repos_main
from sourcegraph_additional_repos_3 import main as sourcegraph_additional_repos_main
from merge_frozen_sboms_4 import main as merge_frozen_sboms_main
from get_all_commits_of_sbom_files_5 import main as get_all_commits_of_sbom_files_main
from github_releases_6 import main as github_releases_main
from download_suspicious_assets_7 import main as download_suspicious_assets_main
from search_inside_assets_8 import main as search_inside_assets_main
from merge_assets_with_sourcegraph_9 import main as merge_assets_with_sourcegraph_main


next_step = ''


def read_next_step(data_folder):
    global next_step
    if not os.path.exists(os.path.join(data_folder, 'next_step.json')):
        # write the first step
        write_next_step(data_folder, 'sourcegraph_init')
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
    timestamp = str(int(time.time()))
    data_folder = os.path.abspath(os.getcwd())
    data_folder = os.path.join(data_folder, f'data_{timestamp}')
    os.mkdir(data_folder)

    #data_folder = os.path.abspath(os.getcwd())
    #data_folder = utils.get_latest_data_folder(data_folder)

    next_step = read_next_step(data_folder)

    if next_step == 'sourcegraph_init':
        # get initial frozen set of SBOM files
        print("Downloading initial SBOM files from Sourcegraph")
        await sourcegraph_main(data_folder)
        write_next_step(data_folder, 'github_additional_repos')

    if next_step == 'github_additional_repos':
        # get other GitHub repositories for author that owns sbom files
        print("Getting additional repositories from GitHub")
        await github_additional_repos_main(data_folder)
        write_next_step(data_folder, 'sourcegraph_additional_repos')

    if next_step == 'sourcegraph_additional_repos':
        # upload additional repos from GH to sourcegraph if those doesn't exist on sourcegraph servers
        # and get the SBOM files from those repos, if there are any
        print("Downloading SBOM files from additional repositories")
        await sourcegraph_additional_repos_main(data_folder)
        write_next_step(data_folder, 'merge_frozen_sboms')

    if next_step == 'merge_frozen_sboms':
        # merge frozen lists from initial and additional runs into our json format
        print("Merging SBOM files")
        await merge_frozen_sboms_main(data_folder)
        write_next_step(data_folder, 'get_all_commits_of_sbom_files')

    if next_step == 'get_all_commits_of_sbom_files':
        # get all commits for each SBOM file from GitHub
        print("Getting all commits for SBOM files")
        await get_all_commits_of_sbom_files_main(data_folder)
        write_next_step(data_folder, 'github_releases')

    if next_step == 'github_releases':
        while True:
            # get releases for each repo that contains SBOM files
            print("Getting releases for each repository")
            checked_all = (await github_releases_main(data_folder))[1]
            if checked_all:
                break
        write_next_step(data_folder, 'download_suspicious_assets')

    if next_step == 'download_suspicious_assets':
        # download suspicious assets (that may contain SBOM information)
        while True:
            print("Downloading suspicious assets")
            res = await download_suspicious_assets_main(data_folder)
            if res == "THRESHOLD_REACHED":
                print("Threshold reached")
                search_inside_assets_main(data_folder)
            elif res == "OK":
                break
        write_next_step(data_folder, 'search_inside_assets')

    if next_step == 'search_inside_assets':
        # search for SBOM information inside those downloaded assets
        print("Searching for SBOM information inside assets")
        search_inside_assets_main(data_folder)
        write_next_step(data_folder, 'merge_assets_with_sourcegraph')

    if next_step == 'merge_assets_with_sourcegraph':
        # merge all SBOM information into one json file
        print("Merging all SBOM information")
        merge_assets_with_sourcegraph_main(data_folder)
        write_next_step(data_folder, 'github_releases_additional_repos')

    if next_step == 'github_releases_additional_repos':
        while True:
            # get releases for all additional repos
            print("Getting releases for all additional repositories")
            checked_all = (await github_releases_main(data_folder, additional_repos=True))[1]
            if checked_all:
                break
            print("Not all repositories were checked, trying again")
        write_next_step(data_folder, 'download_suspicious_assets_additional_repos')

    if next_step == 'download_suspicious_assets_additional_repos':
        # download suspicious assets (that may contain SBOM information)
        while True:
            print("Downloading suspicious assets from additional repositories")
            res = await download_suspicious_assets_main(data_folder, additional_repos=True)
            if res == "THRESHOLD_REACHED":
                print("Threshold reached")
                search_inside_assets_main(data_folder, additional_repos=True)
            elif res == "OK":
                break
        write_next_step(data_folder, 'search_inside_assets_additional_repos')

    if next_step == 'search_inside_assets_additional_repos':
        # search for SBOM information inside those downloaded assets
        print("Searching for SBOM information inside assets")
        search_inside_assets_main(data_folder, additional_repos=True)
        write_next_step(data_folder, 'done')

    if next_step == 'done':
        print("Done")

    return 0


if __name__ == "__main__":
    asyncio.run(main())
