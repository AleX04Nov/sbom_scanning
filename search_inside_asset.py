import os
import re
import tarfile
import zipfile
from shutil import ReadError
from zipfile import ZipFile
from py7zr import unpack_7zarchive, UnsupportedCompressionMethodError

import aiofiles
import aioshutil
import patoolib

import utils

# compile regex filters
global_file_filters         = [re.compile(regex_filter, re.I) for regex_filter in utils.FILE_FILTERS]
spdx_yaml_filters           = [re.compile(regex_filter, re.I) for regex_filter in utils.SPDX_YAML_FILTERS]
spdx_yaml_file_filters      = [re.compile(regex_filter, re.I) for regex_filter in utils.SPDX_YAML_FILE_FILTERS]
spdx_json_filters           = [re.compile(regex_filter, re.I) for regex_filter in utils.SPDX_JSON_FILTERS]
spdx_json_file_filters      = [re.compile(regex_filter, re.I) for regex_filter in utils.SPDX_JSON_FILE_FILTERS]
spdx_spdx_filters           = [re.compile(regex_filter, re.I) for regex_filter in utils.SPDX_SPDX_FILTERS]
spdx_spdx_and_filters       = [re.compile(regex_filter, re.I) for regex_filter in utils.SPDX_SPDX_AND_FILTERS]
spdx_spdx_file_filters      = [re.compile(regex_filter, re.I) for regex_filter in utils.SPDX_SPDX_FILE_FILTERS]
spdx_rdf_filters            = [re.compile(regex_filter, re.I) for regex_filter in utils.SPDX_RDF_FILTERS]
spdx_rdf_file_filters       = [re.compile(regex_filter, re.I) for regex_filter in utils.SPDX_RDF_FILE_FILTERS]
spdx_generic_filters        = [re.compile(regex_filter, re.I) for regex_filter in utils.SPDX_GENERIC_FILTERS]
spdx_generic_file_filters   = [re.compile(regex_filter, re.I) for regex_filter in utils.SPDX_GENERIC_FILE_FILTERS]
cyclonedx_xml_filters       = [re.compile(regex_filter, re.I) for regex_filter in utils.CYCLONEDX_XML_FILTERS]
cyclonedx_xml_file_filters  = [re.compile(regex_filter, re.I) for regex_filter in utils.CYCLONEDX_XML_FILE_FILTERS]
cyclonedx_json_filters      = [re.compile(regex_filter, re.I) for regex_filter in utils.CYCLONEDX_JSON_FILTERS]
cyclonedx_json_file_filters = [re.compile(regex_filter, re.I) for regex_filter in utils.CYCLONEDX_JSON_FILE_FILTERS]

SBOM_TYPES_LIST = [
    'spdx_yaml',
    'spdx_json',
    'spdx_spdx',
    'spdx_rdf',
    'spdx_generic',
    'cyclonedx_xml',
    'cyclonedx_json',
]

ARCHIVE_EXTENSIONS = [".zip", ".tar", ".tgz", ".7z", ".rar", ".gz", ".xz"]


async def check_spdx_file_with_re(filepath, content_filters, file_filters, and_filters) -> bool:
    if any(path_filter.match(filepath) is not None for path_filter in file_filters):
        async with aiofiles.open(filepath, "r", errors='ignore') as f:
            content = await f.read()
        if (
                any(regex_filter.search(content) is not None for regex_filter in content_filters)
                and
                any(and_filter.search(content) is not None for and_filter in and_filters)
        ):
            return True
    return False


async def check_file_with_re(filepath, content_filters, file_filters) -> bool:
    if any(path_filter.match(filepath) is not None for path_filter in file_filters):
        async with aiofiles.open(filepath, "r", errors='ignore') as f:
            content = await f.read()
        if any(regex_filter.search(content) is not None for regex_filter in content_filters):
            return True
    return False


async def check_file(filepath) -> str:
    if await check_file_with_re(filepath, spdx_yaml_filters, spdx_yaml_file_filters):
        return SBOM_TYPES_LIST[0]
    if await check_file_with_re(filepath, spdx_json_filters, spdx_json_file_filters):
        return SBOM_TYPES_LIST[1]
    if await check_spdx_file_with_re(filepath, spdx_spdx_filters, spdx_spdx_file_filters, spdx_spdx_and_filters):
        return SBOM_TYPES_LIST[2]
    if await check_file_with_re(filepath, spdx_rdf_filters, spdx_rdf_file_filters):
        return SBOM_TYPES_LIST[3]
    if await check_file_with_re(filepath, spdx_generic_filters, spdx_generic_file_filters):
        return SBOM_TYPES_LIST[4]
    if await check_file_with_re(filepath, cyclonedx_xml_filters, cyclonedx_xml_file_filters):
        return SBOM_TYPES_LIST[5]
    if await check_file_with_re(filepath, cyclonedx_json_filters, cyclonedx_json_file_filters):
        return SBOM_TYPES_LIST[6]
    return ''


# Dont extract archives recursively
async def check_directory_on_sbom(directory):
    sbom_files = []
    directory = os.path.abspath(directory)
    # find all files with json extension in the current directory
    for root, dirs, files in os.walk(directory):
        for file in files:
            full_file_path = os.path.join(root, file)
            full_file_path_abs = os.path.abspath(full_file_path)
            # remove part of directory path from the full path
            full_file_path = full_file_path_abs.replace(directory + '/', "")
            if any(path_filter.match(full_file_path) is not None for path_filter in global_file_filters):
                continue

            # IM DUMB. JUST IN CASE SEVERAL CHECKS
            # if the is a link, skip it
            if os.path.islink(full_file_path_abs):
                continue
            # if the file is not a regular file, skip it
            if not os.path.isfile(full_file_path_abs):
                continue

            sbom_type = await check_file(full_file_path_abs)
            if sbom_type:
                sbom_file = {"path": full_file_path, "type": sbom_type}
                sbom_files.append(sbom_file)
    return sbom_files


async def main(data_folder, asset_to_check_path: str, asset_name: str) -> tuple[bool, list[dict]]:
    detected_sboms = []

    # get current unpack formats
    # add 7zip to the list of unpack formats
    # if 7zip is not in the list
    unpack_formats = await aioshutil.get_unpack_formats()
    if '7zip' not in [unpack_format[0] for unpack_format in unpack_formats]:
        # register shutil.unpack_archive function for 7zip archives
        await aioshutil.register_unpack_format('7zip', ['.7z'], unpack_7zarchive)

    # check if the asset is an archive
    if asset_name.endswith(tuple(ARCHIVE_EXTENSIONS)):
        unpacked_folder = os.path.join(data_folder, 'unpacked_assets')
        # generate random folder name. Begin with asset name
        unpacked_name = f"{asset_name}_{utils.random_string(16)}"
        unpacked_dir = os.path.join(data_folder, unpacked_folder, unpacked_name)
        try:
            extension: str = asset_name.split('.')[-1]
            if extension.lower() == 'rar':
                patoolib.extract_archive(asset_to_check_path, outdir=unpacked_dir, verbosity=-1, interactive=False)
            else:
                await aioshutil.unpack_archive(asset_to_check_path, unpacked_dir)
        except ReadError:
            try:
                unpacked = False
                if zipfile.is_zipfile(asset_to_check_path):
                    with ZipFile(asset_to_check_path, 'r') as zip_ref:
                        zip_ref.extractall(unpacked_dir)
                        unpacked = True
                if tarfile.is_tarfile(asset_to_check_path):
                    with tarfile.open(asset_to_check_path, 'r') as tar_ref:
                        tar_ref.extractall(unpacked_dir)
                        unpacked = True
                if not unpacked:
                    print(f"Could not extract the archive: {asset_to_check_path}")
                    if not os.path.exists(unpacked_dir):
                        return False, []
            except Exception as e:
                print(f"Error: {e}")
                print(f"Could not extract the archive: {asset_to_check_path}")
                if not os.path.exists(unpacked_dir):
                    return False, []
        except UnsupportedCompressionMethodError as e:
            if "py7zr" in e.args[1]:
                # check if unpacked_dir exists
                # because sometimes this tool can extract at least some data
                if not os.path.exists(unpacked_dir):
                    return False, []
        except Exception as e:
            print(f"Error: {e}")
            print(f"Could not extract the archive: {asset_to_check_path}")
            if not os.path.exists(unpacked_dir):
                return False, []
        # check if unpacked_dir exists
        # because some archives may be empty
        if not os.path.exists(unpacked_dir):
            return False, []
        # check if unpacked_dir contains only one folder
        # if it does, then check the files in that folder
        # if it does not, then check the files in the unpacked_dir
        unpacked_dir_contents = os.listdir(unpacked_dir)
        if len(unpacked_dir_contents) == 1 and os.path.isdir(os.path.join(unpacked_dir, unpacked_dir_contents[0])):
            detected_sboms = await check_directory_on_sbom(os.path.join(unpacked_dir, unpacked_dir_contents[0]))
        else:
            detected_sboms = await check_directory_on_sbom(unpacked_dir)
        # Remove folder after check
        # check if unpacked_dir exists
        # because some archives may be empty
        if os.path.exists(unpacked_dir):
            await aioshutil.rmtree(unpacked_dir)
    else:
        # if this is not an archive, then check the file
        sbom_type = await check_file(asset_to_check_path)
        if sbom_type:
            detected_sboms = [{"path": asset_name, "type": sbom_type}]
    return True, detected_sboms


if __name__ == '__main__':
    # asyncio.run(main())
    pass
