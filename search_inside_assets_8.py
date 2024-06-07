import json
import os
import re
import shutil

import utils

# compile regex filters
file_filters = [re.compile(filter, re.I) for filter in utils.FILE_FILTERS]
spdx_yaml_filters = [re.compile(filter, re.I) for filter in utils.SPDX_YAML_FILTERS]
spdx_yaml_file_filters = [re.compile(filter, re.I) for filter in utils.SPDX_YAML_FILE_FILTERS]
spdx_json_filters = [re.compile(filter, re.I) for filter in utils.SPDX_JSON_FILTERS]
spdx_json_file_filters = [re.compile(filter, re.I) for filter in utils.SPDX_JSON_FILE_FILTERS]
spdx_spdx_filters = [re.compile(filter, re.I) for filter in utils.SPDX_SPDX_FILTERS]
spdx_spdx_file_filters = [re.compile(filter, re.I) for filter in utils.SPDX_SPDX_FILE_FILTERS]
spdx_generic_filters = [re.compile(filter, re.I) for filter in utils.SPDX_GENERIC_FILTERS]
spdx_generic_file_filters = [re.compile(filter, re.I) for filter in utils.SPDX_GENERIC_FILE_FILTERS]
cyclonedx_xml_filters = [re.compile(filter, re.I) for filter in utils.CYCLONEDX_XML_FILTERS]
cyclonedx_xml_file_filters = [re.compile(filter, re.I) for filter in utils.CYCLONEDX_XML_FILE_FILTERS]
cyclonedx_json_filters = [re.compile(filter, re.I) for filter in utils.CYCLONEDX_JSON_FILTERS]
cyclonedx_json_file_filters = [re.compile(filter, re.I) for filter in utils.CYCLONEDX_JSON_FILE_FILTERS]

SBOM_TYPES_LIST = [
    'spdx_yaml',
    'spdx_json',
    'spdx_spdx',
    'spdx_generic',
    'cyclonedx_xml',
    'cyclonedx_json',
]

data_folder = ''


def check_file_with_re(filepath, filters, file_filters):
    for path_filter in file_filters:
        if path_filter.match(filepath) is not None:
            with open(filepath, "r", errors='ignore') as f:
                content = f.read()
            for regex_filter in filters:
                if regex_filter.search(content) is not None:
                    return True
    return False


def check_file(filepath):
    if check_file_with_re(filepath, spdx_yaml_filters, spdx_yaml_file_filters):
        return SBOM_TYPES_LIST[0]
    if check_file_with_re(filepath, spdx_json_filters, spdx_json_file_filters):
        return SBOM_TYPES_LIST[1]
    if check_file_with_re(filepath, spdx_spdx_filters, spdx_spdx_file_filters):
        return SBOM_TYPES_LIST[2]
    if check_file_with_re(filepath, spdx_generic_filters, spdx_generic_file_filters):
        return SBOM_TYPES_LIST[3]
    if check_file_with_re(filepath, cyclonedx_xml_filters, cyclonedx_xml_file_filters):
        return SBOM_TYPES_LIST[4]
    if check_file_with_re(filepath, cyclonedx_json_filters, cyclonedx_json_file_filters):
        return SBOM_TYPES_LIST[5]
    return False


def check_directory_on_sbom(directory, additional_repos=False):
    sbom_files = []
    if additional_repos:
        assets_folder = 'assets_additional'
    else:
        assets_folder = 'assets'
    # find all files with json extension in the current directory
    for root, dirs, files in os.walk(directory):
        for file in files:
            filtered_by_path = True
            for path_filter in file_filters:
                if path_filter.match(os.path.join(root, file)) is not None:
                    filtered_by_path = False
                    break
            if filtered_by_path:
                sbom_type = check_file(os.path.join(root, file))
                if sbom_type:
                    fullpath = os.path.join(root, file)
                    fullpath = fullpath.replace(directory + '/', "")
                    sbom_file = {"path": fullpath, "type": sbom_type}
                    sbom_files.append(sbom_file)
    return sbom_files


def main(folder='', additional_repos=False):
    global data_folder

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    # read 'assets_to_check.json' file
    if additional_repos:
        assets_folder = 'assets_additional'
        with open(os.path.join(data_folder, 'assets_to_check_additional.json'), 'r') as f:
            assets_to_check = json.load(f)
    else:
        assets_folder = 'assets'
        with open(os.path.join(data_folder, "assets_to_check.json"), "r") as f:
            assets_to_check = json.load(f)

    for author in list(assets_to_check.keys()):
        for repo in list(assets_to_check[author].keys()):
            if assets_to_check[author][repo].get("files_to_check") is None:
                continue
            for file_info in assets_to_check[author][repo]["files_to_check"]:
                # check whether this file or directory
                full_path = os.path.join(data_folder, assets_folder, file_info["path"])
                url = file_info["url"]
                if not os.path.exists(full_path):
                    continue
                if os.path.isdir(full_path):
                    # iterate over all files in this directory
                    sboms_from_dir = check_directory_on_sbom(full_path, additional_repos=additional_repos)
                    for sbom in sboms_from_dir:
                        sbom["url"] = url
                    if assets_to_check[author][repo].get("sbom_files") is None:
                        assets_to_check[author][repo]["sbom_files"] = []
                    assets_to_check[author][repo]["sbom_files"].extend(sboms_from_dir)
                    shutil.rmtree(full_path)
                    full_path_archive = os.path.join(data_folder, assets_folder)
                    full_path_archive = os.path.join(full_path_archive, author, repo.split("/")[-1], url.split("/")[-1])
                    os.remove(full_path_archive)
                else:
                    sbom_type = check_file(full_path)
                    os.remove(full_path)
                    if sbom_type:
                        file_path = full_path.replace(os.path.join(data_folder, assets_folder, author, repo.split("/")[-1]) + '/', "")
                        sbom_file = {"path": file_path, "type": sbom_type, 'url': url}
                        if assets_to_check[author][repo].get("sbom_files") is None:
                            assets_to_check[author][repo]["sbom_files"] = []
                        assets_to_check[author][repo]["sbom_files"].append(sbom_file)
            if utils.get_folder_size(os.path.join(data_folder, assets_folder, author, repo.split("/")[-1])) == 0:
                try:
                    shutil.rmtree(os.path.join(data_folder, assets_folder, author, repo.split("/")[-1]))
                except FileNotFoundError:
                    pass
        if utils.get_folder_size(os.path.join(data_folder, assets_folder, author)) == 0:
            try:
                shutil.rmtree(os.path.join(data_folder, assets_folder, author))
            except FileNotFoundError:
                pass

    # remove empty repos
    for author in list(assets_to_check.keys()):
        for repo in list(assets_to_check[author].keys()):
            if assets_to_check[author][repo].get("sbom_files") is None:
                del assets_to_check[author][repo]
            elif assets_to_check[author][repo]["sbom_files"] == []:
                del assets_to_check[author][repo]
        if assets_to_check[author] == {}:
            del assets_to_check[author]

    # dump the sboms_by_author
    assets_to_check_previous = {}
    if additional_repos:
        if os.path.exists(os.path.join(data_folder, 'assets_with_sboms_additional.json')):
            with open(os.path.join(data_folder, 'assets_with_sboms_additional.json'), 'r') as f:
                assets_to_check_previous = json.load(f)
        with open(os.path.join(data_folder, 'assets_with_sboms_additional.json'), 'w') as f:
            for author in assets_to_check_previous:
                if author not in assets_to_check:
                    assets_to_check[author] = assets_to_check_previous[author]
                    continue
                for repo in assets_to_check_previous[author]:
                    if repo not in assets_to_check[author]:
                        assets_to_check[author][repo] = assets_to_check_previous[author][repo]
                        continue
                    else:
                        if assets_to_check[author][repo].get('sbom_files', None) is None:
                            if assets_to_check_previous[author][repo].get('sbom_files', None) is not None:
                                assets_to_check[author][repo]['sbom_files'] = assets_to_check_previous[author][repo]['sbom_files']
                        else:
                            assets_to_check[author][repo]['sbom_files'].extend(assets_to_check_previous[author][repo].get('sbom_files', []))
                            assets_to_check[author][repo]['sbom_files'] = [i for n, i in enumerate(assets_to_check[author][repo]['sbom_files']) if i not in assets_to_check[author][repo]['sbom_files'][n + 1:]]
            for author in list(assets_to_check):
                for repo in list(assets_to_check[author]):
                    if assets_to_check[author][repo].get('releases_to_check') is not None:
                        del assets_to_check[author][repo]['releases_to_check']
                    if assets_to_check[author][repo].get('files_to_check') is not None:
                        del assets_to_check[author][repo]['files_to_check']
                    if assets_to_check[author][repo].get('sbom_files', []) == []:
                        del assets_to_check[author][repo]['sbom_files']
                    if assets_to_check[author][repo] == {}:
                        del assets_to_check[author][repo]
                if assets_to_check[author] == {}:
                    del assets_to_check[author]
            json.dump(assets_to_check, f, indent=4)
    else:
        if os.path.exists(os.path.join(data_folder, 'assets_with_sboms.json')):
            with open(os.path.join(data_folder, 'assets_with_sboms.json'), 'r') as f:
                assets_to_check_previous = json.load(f)
        with open(os.path.join(data_folder, 'assets_with_sboms.json'), 'w') as f:
            for author in assets_to_check_previous:
                if author not in assets_to_check:
                    assets_to_check[author] = assets_to_check_previous[author]
                    continue
                for repo in assets_to_check_previous[author]:
                    if repo not in assets_to_check[author]:
                        assets_to_check[author][repo] = assets_to_check_previous[author][repo]
                        continue
                    else:
                        if assets_to_check[author][repo].get('sbom_files', None) is None:
                            if assets_to_check_previous[author][repo].get('sbom_files', None) is not None:
                                assets_to_check[author][repo]['sbom_files'] = \
                                assets_to_check_previous[author][repo]['sbom_files']
                        else:
                            assets_to_check[author][repo]['sbom_files'].extend(
                                assets_to_check_previous[author][repo].get('sbom_files', []))
                            assets_to_check[author][repo]['sbom_files'] = [i for n, i in enumerate(assets_to_check[author][repo]['sbom_files']) if i not in assets_to_check[author][repo]['sbom_files'][n + 1:]]
            for author in list(assets_to_check):
                for repo in list(assets_to_check[author]):
                    if assets_to_check[author][repo].get('releases_to_check') is not None:
                        del assets_to_check[author][repo]['releases_to_check']
                    if assets_to_check[author][repo].get('files_to_check') is not None:
                        del assets_to_check[author][repo]['files_to_check']
                    if assets_to_check[author][repo].get('sbom_files', []) == []:
                        del assets_to_check[author][repo]['sbom_files']
                    if assets_to_check[author][repo] == {}:
                        del assets_to_check[author][repo]
                if assets_to_check[author] == {}:
                    del assets_to_check[author]
            json.dump(assets_to_check, f, indent=4)

    return True


if __name__ == '__main__':
    main()
