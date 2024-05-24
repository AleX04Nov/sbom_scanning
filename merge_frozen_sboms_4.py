import asyncio
import json
import os

import utils

data_folder = ''


async def main(folder=''):
    global data_folder

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    # open the frozen file
    filename = 'additional_repos_sourcegraph_frozen_raw.json'
    filename = os.path.join(data_folder, filename)
    with open(filename, 'r') as f:
        sbom_dict = json.load(f)

    sboms_by_author = {}
    for key in sbom_dict:
        print(f"Successfully loaded the SBOM urls for `{key}` . Total: {len(sbom_dict[key])}")
        for sbom in sbom_dict[key]:
            repo = sbom['repository']['name']
            repo_author = sbom['repository']['url'].split('/')[-2]
            if repo_author not in sboms_by_author:
                sboms_by_author[repo_author] = {}
            if repo not in sboms_by_author[repo_author]:
                sboms_by_author[repo_author][repo] = []
            filedata_to_append = {
                'path': sbom['file']['path'],
                'url': f'https://{repo}/blob/{sbom["file"]["commit"]["oid"]}/{sbom["file"]["path"]}'
            }
            sboms_by_author[repo_author][repo].append(filedata_to_append)
    # dump the sboms_by_author
    with open(os.path.join(data_folder, 'additional_sboms_by_author.json'), 'w') as f:
        json.dump(sboms_by_author, f, indent=4)

    # open sourcegraph_frozen_raw.json
    filename = 'sourcegraph_frozen_raw.json'
    filename = os.path.join(data_folder, filename)
    with open(filename, 'r') as f:
        sbom_dict = json.load(f)
    for key in sbom_dict:
        print(f"Successfully loaded the SBOM urls for `{key}` . Total: {len(sbom_dict[key]['Results'])}")
        for sbom in sbom_dict[key]['Results']:
            repo = sbom['repository']['name']
            repo_author = sbom['repository']['url'].split('/')[-2]
            if repo_author not in sboms_by_author:
                sboms_by_author[repo_author] = {}
            if repo not in sboms_by_author[repo_author]:
                sboms_by_author[repo_author][repo] = []
            filedata_to_append = {
                'path': sbom['file']['path'],
                'url': f'https://{repo}/blob/{sbom["file"]["commit"]["oid"]}/{sbom["file"]["path"]}'
            }
            sboms_by_author[repo_author][repo].append(filedata_to_append)

    # sort the sboms_by_author by author name
    sboms_by_author = dict(sorted(sboms_by_author.items()))

    with open(os.path.join(data_folder, 'all_sboms_by_author.json'), 'w') as f:
        json.dump(sboms_by_author, f, indent=4)
    return


if __name__ == '__main__':
    asyncio.run(main())
