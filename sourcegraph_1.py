import os
import time

import asyncio
import json

import utils


QUERY_LIST = [
    ('spdx_yaml', (utils.SPDX_YAML_FILTERS, utils.SPDX_YAML_FILE_FILTERS)),
    ('spdx_json', (utils.SPDX_JSON_FILTERS, utils.SPDX_JSON_FILE_FILTERS)),
    ('spdx_spdx', (utils.SPDX_SPDX_FILTERS, utils.SPDX_SPDX_FILE_FILTERS)),
    ('spdx_generic', (utils.SPDX_GENERIC_FILTERS, utils.SPDX_GENERIC_FILE_FILTERS)),
    ('cyclonedx_xml', (utils.CYCLONEDX_XML_FILTERS, utils.CYCLONEDX_XML_FILE_FILTERS)),
    ('cyclonedx_json', (utils.CYCLONEDX_JSON_FILTERS, utils.CYCLONEDX_JSON_FILE_FILTERS))
]
SRC_ENV = {
    'SRC_ENDPOINT': 'https://sourcegraph.com',
    'SRC_ACCESS_TOKEN': ''
}
data_folder = ''

async def sourcegraph_cli_get_sboms(query: str) -> list:
    # call sourcegraph cli
    result = []
    cmd = f"src search -json -- $'{query}'"
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        print(stderr.decode())
    if stdout:
        result = json.loads(stdout)
    return result


async def main(folder=''):
    global data_folder, SRC_ENV

    if folder == '':
        timestamp = str(int(time.time()))
        data_folder = os.path.abspath(os.getcwd())
        data_folder = os.path.join(data_folder, f'data_{timestamp}')
        os.mkdir(data_folder)
    else:
        data_folder = folder
        # create data folder if it does not exist
        if not os.path.exists(data_folder):
            os.mkdir(data_folder)

    # set env vars
    with open('sourcegraph_token.txt', 'r') as f:
        SRC_ENV['SRC_ACCESS_TOKEN'] = f.readline().strip()
    os.environ.update(SRC_ENV)

    sbom_dict = {}
    # get the sbom urls
    for query_name, query_details in QUERY_LIST:
        # create query for sourcegraph
        query = utils.SOURCEGRAPH_SEARCH_OPTIONS
        for filter in utils.FILE_FILTERS:
            query += f' -file:{filter}'
        for filter in utils.REPO_FILTERS:
            query += f' -repo:{filter}'
        for filter in query_details[0]:
            query += f' /{filter}/ OR'
        if len(query_details[0]) > 0:
            query = query[:-3]
        for filter in query_details[1]:
            query += f' file:{filter}'
        sbom_dict[query_name] = await sourcegraph_cli_get_sboms(query)
        print(f"Successfully got the SBOM urls for `{query_name}` .")
        print(f"Total: {len(sbom_dict[query_name]['Results'])}")

    # create file with timestamp in name and store sbom_dict
    sbom_dict_filename = 'sourcegraph_frozen_raw.json'
    with open(os.path.join(data_folder, sbom_dict_filename), 'w') as f:
        json.dump(sbom_dict, f)
    print("Successfully downloaded all the SBOMs")


if __name__ == '__main__':
    asyncio.run(main())
