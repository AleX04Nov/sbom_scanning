import asyncio
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


async def main():
    timestamp = str(int(time.time()))
    data_folder = os.path.abspath(os.getcwd())
    data_folder = os.path.join(data_folder, f'data_{timestamp}')
    os.mkdir(data_folder)

    # data_folder = os.path.abspath(os.getcwd())
    # data_folder = utils.get_latest_data_folder(data_folder)

    # get initial frozen set of SBOM files
    print("Downloading initial SBOM files from Sourcegraph")
    await sourcegraph_main(data_folder)

    # get other GitHub repositories for author that owns sbom files
    print("Getting additional repositories from GitHub")
    await github_additional_repos_main(data_folder)

    # upload additional repos from GH to sourcegraph if those doesn't exist on sourcegraph servers
    # and get the SBOM files from those repos, if there are any
    print("Downloading SBOM files from additional repositories")
    await sourcegraph_additional_repos_main(data_folder)

    # merge frozen lists from initial and additional runs into our json format
    print("Merging SBOM files")
    await merge_frozen_sboms_main(data_folder)

    # get all commits for each SBOM file from GitHub
    print("Getting all commits for SBOM files")
    await get_all_commits_of_sbom_files_main(data_folder)

    # get releases for each repo that contains SBOM files
    print("Getting releases for each repository")
    await github_releases_main(data_folder)

    # download suspicious assets (that may contain SBOM information)
    print("Downloading suspicious assets")
    await download_suspicious_assets_main(data_folder)

    # search for SBOM information inside those downloaded assets
    print("Searching for SBOM information inside assets")
    search_inside_assets_main(data_folder)

    return 0


if __name__ == "__main__":
    asyncio.run(main())
