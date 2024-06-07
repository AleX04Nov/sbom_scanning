import asyncio
import json
import os

import aiofiles as aiof
import aioshutil

import utils
import aiohttp

data_folder = ''
sbom_folder = 'sbom_files'
session: aiohttp.ClientSession = None
ARCHIVE_EXTENSIONS = [".zip", ".tar", ".tgz", ".7z", ".rar", ".gz", ".xz"]


async def download_gh_raw_file(url):
    global session
    async with session.get(url) as response:
        url_file_name = url.split('/')[-1]
        extension = url_file_name.split('.')[-1]
        if response.status == 200:
            file_content = await response.text()
            # create unique random file name
            while True:
                random_file_name = utils.random_string(20) + '.' + extension
                if not os.path.exists(os.path.join(data_folder, sbom_folder, random_file_name)):
                    break
            with open(os.path.join(data_folder, 'sbom_files', random_file_name), 'w') as f:
                f.write(file_content)
            return random_file_name
        else:
            return ""


async def download_gh_release_file(url, path):
    global session
    isArchive = False
    async with session.get(url, timeout=None) as response:
        url_file_name = url.split('/')[-1]
        url_extension_url = '.' + url_file_name.split('.')[-1]
        for url_extension in ARCHIVE_EXTENSIONS:
            if url_extension in url_extension_url:
                isArchive = True
        while True:
            random_file_name = utils.random_string(20) + url_extension_url
            if not os.path.exists(os.path.join(data_folder, sbom_folder, random_file_name)):
                break
        if isArchive:
            random_file_name += '_' + url.split('/')[-1]
        async with aiof.open(os.path.join(data_folder, f"{sbom_folder}/{random_file_name}"), 'wb') as f:
            await f.write(await response.read())
            await f.flush()
        if isArchive:
            await aioshutil.unpack_archive(
                os.path.join(data_folder, f"{sbom_folder}/{random_file_name}"),
                os.path.join(data_folder, f"{sbom_folder}/{random_file_name[:-len(url_extension_url)]}")
            )
            # remove the original archive file
            os.remove(os.path.join(data_folder, f"{sbom_folder}/{random_file_name}"))
            random_file_name = random_file_name[:-len(url_extension_url)]
            # get the file form the extracted folder
            file_in_archive_path = os.path.join(data_folder, f"{sbom_folder}/{random_file_name}", path)
            if os.path.exists(file_in_archive_path):
                # copy the file to the sbom_files folder
                while True:
                    new_random_file_name = utils.random_string(20) + '.' + (path.split('/')[-1]).split('.')[-1]
                    if not os.path.exists(os.path.join(data_folder, sbom_folder, new_random_file_name)):
                        break
                await aioshutil.copy(file_in_archive_path, os.path.join(data_folder, f"{sbom_folder}/{new_random_file_name}"))
                # remove the extracted folder
                await aioshutil.rmtree(os.path.join(data_folder, f"{sbom_folder}/{random_file_name}"))
                print("Removing the extracted folder: ", os.path.join(data_folder, f"{sbom_folder}/{random_file_name}"))
                return new_random_file_name
            else:
                print(f"File not found in the archive: {file_in_archive_path}")
                return ""
        else:
            return random_file_name
    return ""


async def download_gh_sbom(sbom_object):
    url = sbom_object['url']
    splitted = url.split('/')
    if splitted[5] == 'releases':
        file_name = await download_gh_release_file(url, sbom_object['path'])
        if file_name != "":
            sbom_object['file_name'] = file_name
    elif splitted[5] == 'blob':
        url = url.replace('https://github.com', 'https://raw.githubusercontent.com')
        url = url.replace('blob/', '')
        file_name = await download_gh_raw_file(url)
        if file_name != "":
            sbom_object['file_name'] = file_name


async def download_sg_sbom(sbom_object):
    url = sbom_object['url']
    url = url.replace('/-/blob/', '/-/raw/')
    async with session.get(url) as response:
        url_filename = url.split('/')[-1]
        extension = url_filename.split('.')[-1]
        if response.status == 200:
            file_content = await response.text()
            # create unique random file name
            while True:
                random_file_name = utils.random_string(20) + '.' + extension
                if not os.path.exists(os.path.join(data_folder, sbom_folder, random_file_name)):
                    break
            with open(os.path.join(data_folder, 'sbom_files', random_file_name), 'w') as f:
                f.write(file_content)
            sbom_object['file_name'] = random_file_name
        else:
            sbom_object['file_name'] = ""



async def main(folder=''):
    global data_folder, session
    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder

    session = aiohttp.ClientSession()

    with open(os.path.join(data_folder, 'res_sbom_list.json'), 'r') as f:
        sboms_by_author = json.load(f)

    os.makedirs(os.path.join(data_folder, f"{sbom_folder}"), exist_ok=True)

    for author in sboms_by_author:
        for repo in sboms_by_author[author]:
            for sbom in sboms_by_author[author][repo]:
                if 'https://github.com/' in sbom['url']:
                    await download_gh_sbom(sbom)
                if 'https://sourcegraph.com/' in sbom['url']:
                    await download_sg_sbom(sbom)

    # remove repos that we couldnt download sbom files
    for author in list(sboms_by_author):
        for repo in list(sboms_by_author[author]):
            for sbom in list(sboms_by_author[author][repo]):
                if sbom.get('file_name', "") == "":
                    sboms_by_author[author][repo].remove(sbom)
            if len(sboms_by_author[author][repo]) == 0:
                del sboms_by_author[author][repo]
        if len(sboms_by_author[author]) == 0:
            del sboms_by_author[author]

    with open(os.path.join(data_folder, 'downloaded_sboms_list.json'), 'w') as f:
        json.dump(sboms_by_author, f, indent=4)

    await session.close()

    return 0


if __name__ == "__main__":
    asyncio.run(main())
