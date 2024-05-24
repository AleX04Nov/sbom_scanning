import json
import os
import re
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


def check_directory_on_sbom(directory):
    sbom_files = []
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
                    fullpath = fullpath.replace(os.path.join(data_folder, 'assets'), "")
                    sbom_file = {"filename": fullpath, "type": sbom_type}
                    sbom_files.append(sbom_file)
    return sbom_files


def main(folder=''):
    global data_folder

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    # read 'assets_to_check.json' file
    with open(os.path.join(data_folder, "assets_to_check.json"), "r") as f:
        assets_to_check = json.load(f)

    for author in list(assets_to_check.keys()):
        for repo in list(assets_to_check[author].keys()):
            assets_to_check[author][repo]["sbom_files"] = []
            for path in assets_to_check[author][repo]["files_to_check"]:
                # check whether this file or directory
                full_path = os.path.join(data_folder, 'assets')
                full_path = os.path.join(full_path, path)
                if os.path.isdir(full_path):
                    # iterate over all files in this directory
                    assets_to_check[author][repo]["sbom_files"].extend(check_directory_on_sbom(full_path))
                else:
                    sbom_type = check_file(full_path)
                    if sbom_type:
                        full_path = full_path.replace(os.path.join(data_folder, 'assets'), "")
                        sbom_file = {"filename": full_path, "type": sbom_type}
                        assets_to_check[author][repo]["sbom_files"].append(sbom_file)

    # dump the sboms_by_author
    with open(os.path.join(data_folder, 'assets_with_sboms.json'), 'w') as f:
        json.dump(assets_to_check, f, indent=4)

    return True


if __name__ == '__main__':
    main()
