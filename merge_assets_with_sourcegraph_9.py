import json
import os

import utils

data_folder = ''


def main(folder=''):
    global data_folder

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    res_sbom_list = {}
    # read 'assets_to_check.json' file
    with open(os.path.join(data_folder, "assets_with_sboms.json"), "r") as f:
        assets_with_sboms = json.load(f)

    with open(os.path.join(data_folder, "all_sboms_by_author.json"), "r") as f:
        all_sboms_by_author = json.load(f)

    for author in list(assets_with_sboms.keys()):
        for repo in list(assets_with_sboms[author].keys()):
            for sbom in assets_with_sboms[author][repo]["sbom_files"]:
                if author not in res_sbom_list:
                    res_sbom_list[author] = {}
                if repo not in res_sbom_list[author]:
                    res_sbom_list[author][repo] = []
                res_sbom_list[author][repo].append(sbom)
    for author in list(all_sboms_by_author.keys()):
        for repo in list(all_sboms_by_author[author].keys()):
            for sbom in all_sboms_by_author[author][repo]:
                if author not in res_sbom_list:
                    res_sbom_list[author] = {}
                if repo not in res_sbom_list[author]:
                    res_sbom_list[author][repo] = []
                res_sbom_list[author][repo].append(sbom)

    # dump the res_sbom_list
    with open(os.path.join(data_folder, 'res_sbom_list.json'), 'w') as f:
        json.dump(res_sbom_list, f, indent=4)


if __name__ == '__main__':
    main()
