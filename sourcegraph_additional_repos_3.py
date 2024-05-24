import asyncio
import json
import os
import random

import aiohttp

import utils

REPO_SEM = asyncio.Semaphore(30)
URL_SEM = asyncio.Semaphore(120)
CLI_SEM = asyncio.Semaphore(120)

MIN_TIMEOUT = 2
MAX_TIMEOUT = 10

FAILED_REPO_FILE_LOCK = asyncio.Lock()
FAILED_REPO_FILE_NAME = 'failed_repos.txt'

EMPTY_REPO_FILE_LOCK = asyncio.Lock()
EMPTY_REPO_FILE_NAME = 'empty_repos.txt'

TOO_MANY_REQUESTS = b'error: 429 Too Many Requests\n\nerror code: 1015\n'
TCP_IO_TIMEOUT = b'Post "https://sourcegraph.com/.api/graphql": dial tcp '
GENERIC_GRAPHQL_POST_ERR = b'Post "https://sourcegraph.com/.api/graphql":'
GENERIC_GRAPHQL_ERR = b'GraphQL errors: {'
BAD_GATEWAY = b'error: 502 Bad Gateway\n\n'
INTERNAL_SERVER_ERROR = b'error: 500 Internal Server Error'
NO_REPOS_ALERT = "No repositories found"
aio_session: aiohttp.ClientSession
data_folder = ''

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


async def add_failed_repo(repo_url: str):
    async with FAILED_REPO_FILE_LOCK:
        with open(os.path.join(data_folder, FAILED_REPO_FILE_NAME), 'a') as f:
            f.write(f"{repo_url}\n")


async def add_empty_repo(repo_url: str):
    async with EMPTY_REPO_FILE_LOCK:
        with open(os.path.join(data_folder, EMPTY_REPO_FILE_NAME), 'a') as f:
            f.write(f"{repo_url}\n")


def get_repos_from_sourcegraph(filename: str) -> list:
    # open file and load json data
    with open(filename, 'r') as f:
        sourcegraph_data = json.load(f)
    unique_repos = set()
    for item in sourcegraph_data:
        for result in sourcegraph_data[item]['Results']:
            if result['repository']['name'][:10] == 'github.com':
                unique_repos.add(result['repository']['name'])
            #else:
            #   print(f"Unknown repository: {result['repository']['name']} in query: {item}")
    return list(sorted(unique_repos))


async def sourcegraph_clone_repo(repo_name) -> bool:
    # open website to clone repo
    url = f'https://sourcegraph.com/{repo_name}'
    i = 0
    while True:
        if i > 7:
            return False
        i += 1
        # print(f"Cloning {repo_name}")
        async with URL_SEM:
            try:
                async with aio_session.request(
                        method='get',
                        url=url,
                        headers={'Authorization': f'token {SRC_ENV["SRC_ACCESS_TOKEN"]}'}
                ) as resp:
                    if resp.status == 404:
                        time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                        await asyncio.sleep(time_to_sleep)
                        continue
                    elif resp.status == 500:
                        time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                        await asyncio.sleep(time_to_sleep)
                        continue
                    elif resp.status != 200:
                        Exception(f"Failed to open {url}")
            except aiohttp.client_exceptions.ClientConnectorError as e:
                time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                await asyncio.sleep(time_to_sleep)
                continue
            except asyncio.TimeoutError as e:
                time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                await asyncio.sleep(time_to_sleep)
                continue
            except aiohttp.client_exceptions.ServerDisconnectedError as e:
                time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                await asyncio.sleep(time_to_sleep)
                continue
            except aiohttp.client_exceptions.ClientOSError as e:
                time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                await asyncio.sleep(time_to_sleep)
                continue
        return True


async def sourcegraph_cli_query(query: str, repo_url: str) -> list:
    result = []
    cmd = f"src search -json -- $'{query}'"
    while True:
        async with CLI_SEM:
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    close_fds=True,
                )
                stdout, stderr = await proc.communicate()
                if stderr:
                    if TOO_MANY_REQUESTS == stderr:
                        time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                        await asyncio.sleep(time_to_sleep)
                        continue
                    elif TCP_IO_TIMEOUT == stderr:
                        time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                        await asyncio.sleep(time_to_sleep)
                        continue
                    elif GENERIC_GRAPHQL_POST_ERR in stderr:
                        time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                        await asyncio.sleep(time_to_sleep)
                        continue
                    elif GENERIC_GRAPHQL_ERR in stderr:
                        time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                        await asyncio.sleep(time_to_sleep)
                        continue
                    elif BAD_GATEWAY in stderr:
                        time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                        await asyncio.sleep(time_to_sleep)
                        continue
                    elif INTERNAL_SERVER_ERROR in stderr:
                        time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                        await asyncio.sleep(time_to_sleep)
                        continue
                    else:
                        print(stderr.decode())
                        time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                        await asyncio.sleep(time_to_sleep)
                        continue
                if stdout:
                    json_output = json.loads(stdout)
            except OSError as e:
                if e.errno != 24:
                    print(f"Failed to run src search: {e}")
                time_to_sleep = random.uniform(MIN_TIMEOUT, MAX_TIMEOUT)
                await asyncio.sleep(time_to_sleep)
                continue
        if json_output['Alert']['Title'] == NO_REPOS_ALERT:
            bool_res = await sourcegraph_clone_repo(repo_url)
            if bool_res is False:
                print(f"Failed to clone {repo_url}")
                await add_failed_repo(repo_url)
                return False
            else:
                print(f"Cloned {repo_url}")
            await asyncio.sleep(5)
            continue
        if len(json_output['Cloning']) != 0 or len(json_output['Timedout']) != 0:
            await asyncio.sleep(5)
            continue
        else:
            result = json_output['Results']
            break
    if len(result) != 0:
        a=1

    return result


async def sourcegraph_cli_queries(repo_url: str) -> dict:
    # create a query for each file type
    results = {}
    is_empty = True

    async with REPO_SEM:
        for query_name, query_details in QUERY_LIST:
            query = utils.SOURCEGRAPH_SEARCH_OPTIONS
            for filter in utils.FILE_FILTERS:
                query += f' -file:{filter}'
            query += f' repo:^{repo_url}$'
            for filter in query_details[0]:
                query += f' /{filter}/ OR'
            if len(query_details[0]) > 0:
                query = query[:-3]
            for filter in query_details[1]:
                query += f' file:{filter}'
            results[query_name] = await sourcegraph_cli_query(query, repo_url)
            if results[query_name] is False:
                return results
            if len(results[query_name]) != 0:
                is_empty = False
            await asyncio.sleep(1.3)
    if is_empty:
        await add_empty_repo(repo_url)
    return results

async def sourcegraph_cli_queries_all(repo_url_list: list) -> dict:
    all_results = {}
    not_cloned_repos = []
    # create a query for each file type
    results = await asyncio.gather(*[sourcegraph_cli_queries(repo_url) for repo_url in repo_url_list],
                                   return_exceptions=False)
    for dict_result in results:
        for query_name in dict_result:
            if dict_result[query_name] is False:
                continue
            if query_name not in all_results:
                all_results[query_name] = []
            all_results[query_name].extend(dict_result[query_name])

    return all_results


async def main(folder=''):
    global aio_session, data_folder, SRC_ENV

    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    aio_session = aiohttp.ClientSession()

    # set env vars
    with open('sourcegraph_token.txt', 'r') as f:
        SRC_ENV['SRC_ACCESS_TOKEN'] = f.readline().strip()
    os.environ.update(SRC_ENV)

    filename = 'sourcegraph_frozen_raw.json'
    filename = os.path.join(data_folder, filename)
    already_scanned = set(get_repos_from_sourcegraph(filename))

    # read additional repos from file
    if os.path.exists(os.path.join(data_folder, 'additional_repos.txt')):
        with open(os.path.join(data_folder, 'additional_repos.txt'), 'r') as f:
            additional_repos = set([line.strip() for line in f])
    else:
        print("No additional repos found")
        return 0
    repos_to_scan = additional_repos - already_scanned

    # read failed repos from file
    if os.path.exists(os.path.join(data_folder, FAILED_REPO_FILE_NAME)):
        with open(os.path.join(data_folder, FAILED_REPO_FILE_NAME), 'r') as f:
            failed_repos = set([line.strip() for line in f])
        repos_to_scan = repos_to_scan - failed_repos

    # read empty repos from file
    if os.path.exists(os.path.join(data_folder, EMPTY_REPO_FILE_NAME)):
        with open(os.path.join(data_folder, EMPTY_REPO_FILE_NAME), 'r') as f:
            empty_repos = set([line.strip() for line in f])
        repos_to_scan = repos_to_scan - empty_repos

    # exclude ignored repos
    repos_to_scan = repos_to_scan - set(utils.IGNORED_REPOS)

    repos_results = await sourcegraph_cli_queries_all(list(repos_to_scan))

    sbom_dict_filename = 'additional_repos_sourcegraph_frozen_raw.json'
    sbom_dict_filename = os.path.join(data_folder, sbom_dict_filename)
    with open(sbom_dict_filename, 'w') as f:
        json.dump(repos_results, f)
    print("Successfully downloaded all ITER2 SBOMs")

    # close aio session
    await aio_session.close()
    return 0


if __name__ == '__main__':
    asyncio.run(main())
