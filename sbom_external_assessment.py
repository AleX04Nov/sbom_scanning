import asyncio
import os

import utils
import json


data_folder = ''
sbom_folder = 'sbom_files'


async def sbomqs_assessment(sbom_file_path):
    # call sbomqs
    output_file = sbom_file_path + '.sbomqs'
    proc = await asyncio.create_subprocess_exec(
        'sbomqs', 'score', '--json', sbom_file_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        close_fds=True,
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        print("Error in sbomqs_assessment")
    if stdout:
        if 'failed to parse' in stdout.decode()[:15]:
            return ""
        sbomqs_json = json.loads(stdout.decode())
        with open(output_file, 'w') as f:
            json.dump(sbomqs_json, f, indent=4)
        return output_file
    return ""


async def osv_scanner_assessment(sbom_file_path):
    output_file = sbom_file_path + '.osv'
    proc = await asyncio.create_subprocess_exec(
        'osv-scanner', 'scan', '--format', 'json', '--sbom', sbom_file_path, '--output', output_file,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        close_fds=True,
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        if "Scanned" not in stderr.decode()[:7]:
            print(f"Error in osv_scanner_assessment during looking at {sbom_file_path}: ", stderr.decode())
            # remove the file if it's exists
            if os.path.exists(output_file):
                os.remove(output_file)
            return ""
    return output_file


async def cyclonedx_assessment(sbom_file_path, sbom_type='autodetect'):
    proc = await asyncio.create_subprocess_exec(
        'cyclonedx', 'validate', '--input-file', sbom_file_path, '--input-format', sbom_type,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        close_fds=True,
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        print("Error in cyclonedx_assessment")
    if stdout:
        if "BOM validated successfully" in stdout.decode():
            return True
    return False


async def sbom_utility_assessment(sbom_file_path):
    proc = await asyncio.create_subprocess_exec(
        'sbom-utility', 'validate', '--input-file', sbom_file_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        close_fds=True,
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        print("Error in sbom_utility_assessment")
    if stdout:
        if "BOM valid against JSON schema: `true`" in stdout.decode():
            return True
    return False


async def spdx_tool_assessment(sbom_file_path):
    proc = await asyncio.create_subprocess_exec(
        'pyspdxtools', '--infile', sbom_file_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        close_fds=True,
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        print("Error in spdx_tool_assessment")
        return False
    if stdout:
        return False
    return True


async def ntia_assessment(sbom_file_path):
    output_file = sbom_file_path + '.ntia'
    proc = await asyncio.create_subprocess_exec(
        'ntia-checker', '--file', sbom_file_path, '--skip-validation', '--output',  'json',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        close_fds=True,
    )
    stdout, stderr = await proc.communicate()
    if stderr:
        print("Error in ntia_assessment")
    if stdout:
        ntia_json = json.loads(stdout.decode())
        if ntia_json.get("parsingError"):
            return ""
        with open(output_file, 'w') as f:
            json.dump(ntia_json, f, indent=4)
        return output_file
    return ""


async def external_assessment(sboms_by_author):
    for author in sboms_by_author:
        for repo in sboms_by_author[author]:
            for sbom in sboms_by_author[author][repo]:
                print("="*23)
                print(f"Assessing {sbom['file_name']}")
                sbom_full_path = os.path.join(sbom_folder, sbom['file_name'])
                # do sbomqs assessment (can do all types of sboms)
                print("Doing sbomqs assessment")
                sbomqs_output_file = await sbomqs_assessment(sbom_full_path)
                if sbomqs_output_file:
                    # remove sbom_folder_path from the output file path
                    sbomqs_output_file = sbomqs_output_file.replace(sbom_folder + '/', '')
                    sbom['sbomqs_file'] = sbomqs_output_file
                # do osv-scanner assessment (can't scan spdx_yaml files)
                if sbom["type"] != "spdx_yaml":
                    print("Doing osv-scanner assessment")
                    osv_output_file = await osv_scanner_assessment(sbom_full_path)
                    # remove sbom_folder_path from the output file path
                    osv_output_file = osv_output_file.replace(sbom_folder + '/', '')
                    if osv_output_file:
                        sbom['osv_file'] = osv_output_file
                # do sbom-utility assessment (only jsons from all cyclones and some from spdx)
                if sbom["type"] == "spdx_json" or sbom["type"] == "cyclonedx_json":
                    # do sbom-utility assessment
                    print("Doing sbom-utility assessment")
                    sbom['sbom_utility'] = await sbom_utility_assessment(sbom_full_path)
                if sbom["type"] == "cyclonedx_json" or sbom["type"] == "cyclonedx_xml":
                    # do cyclonedx assessment with cyclone (can do all types of cyclonedx sboms)
                    print("Doing cyclonedx assessment")
                    sbom_type = "json" if sbom["type"] == "cyclonedx_json" else "xml"
                    sbom['cyclonedx'] = await cyclonedx_assessment(sbom_full_path, sbom_type)
                if sbom["type"][:4] == "spdx":
                    # do spdx assessment with spdxs-tool (can do only SPDX-2.2+ versions)
                    print("Doing pyspdxtool assessment")
                    sbom['spdx_tool'] = await spdx_tool_assessment(sbom_full_path)
                    # do spdx assessment with ntia
                    print("Doing ntia assessment")
                    ntia_output_file = await ntia_assessment(sbom_full_path)
                    if ntia_output_file:
                        # remove sbom_folder_path from the output file path
                        ntia_output_file = ntia_output_file.replace(sbom_folder + '/', '')
                        sbom['ntia_file'] = ntia_output_file
                print("="*23)
                print()
    return sboms_by_author


async def main(folder=''):
    global data_folder, sbom_folder
    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder
    sbom_folder = os.path.join(data_folder, sbom_folder)

    os.environ.update({'INTERLYNK_DISABLE_VERSION_CHECK': '1'})

    sboms_by_author = {}
    with open(os.path.join(data_folder, 'downloaded_sbom_list.json'), 'r') as f:
        sboms_by_author = json.load(f)

    sboms_by_author = await external_assessment(sboms_by_author)

    with open(os.path.join(data_folder, 'assessed_sbom_list.json'), 'w') as f:
        json.dump(sboms_by_author, f, indent=4)

    return 0


if __name__ == "__main__":
    asyncio.run(main())
