import os

import tarfile
import zipfile
from shutil import ReadError
from zipfile import ZipFile
from py7zr import unpack_7zarchive, UnsupportedCompressionMethodError

import aiofiles
import aioshutil
import patoolib

SOURCEGRAPH_SEARCH_OPTIONS = 'context:global archived:yes fork:yes count:all'

IGNORED_REPOS = [
    "github.com/apache/airflow-site",
    "github.com/Be-Secure/besecure-assessment-datastore",
    "github.com/chainguard-dev/bom-shelter",
    "github.com/chains-project/SBOM-2023",
    "github.com/chains-project/sbom-files",
    "github.com/cybeats/sbomgen",
    "github.com/CycloneDX/bom-examples",
    "github.com/CycloneDX/cyclonedx-dotnet-library",
    "github.com/endorlabs/sbom-lab",
    "github.com/garethr/snyk-sbom-examples",
    "github.com/guacsec/guac-data",
    "github.com/k3rn3Lp4n1cK/ctf-live-build-config",
    "github.com/maxhbr/LicenseScannerComparison",
    "github.com/mercedes-benz/sechub",
    "github.com/nexB/spdx-license-namespaces-registry",
    "github.com/Open-Source-Compliance/package-analysis",
    "github.com/opencybersecurityalliance/casp",
    "github.com/OSSQA-PUM/OSSQA",
    "github.com/PanZheng-2021/xhs",
    "github.com/phil2211/deciphering_complexity",
    "github.com/rad-security/fingerprints",
    "github.com/sonatype-nexus-community/cyclonedx-sbom-examples",
    "github.com/spdx/spdx-examples",
    "github.com/spdx/license-list-data",
    "github.com/SEMICeu/DCAT-AP",
]

# create valid regex filter for ignored repos
REPO_FILTERS = [
    r'^github\.com/('
]
for repo in IGNORED_REPOS:
    REPO_FILTERS[0] += repo[repo.find("/") + 1:] + '|'
REPO_FILTERS[0] = REPO_FILTERS[0][:-1] + r')$'

# REPO_FILTERS = [
#    r'^github\.com/(apache/airflow-site|Be-Secure/besecure-assessment-datastore|chainguard-dev/bom-shelter|chains-project/SBOM-2023|chains-project/sbom-files|cybeats/sbomgen|CycloneDX/bom-examples|CycloneDX/cyclonedx-dotnet-library|endorlabs/sbom-lab|garethr/snyk-sbom-examples|guacsec/guac-data|k3rn3Lp4n1cK/ctf-live-build-config|maxhbr/LicenseScannerComparison|mercedes-benz/sechub|Open-Source-Compliance/package-analysis|opencybersecurityalliance/casp|OSSQA-PUM/OSSQA|PanZheng-2021/xhs|phil2211/deciphering_complexity|rad-security/fingerprints|sonatype-nexus-community/cyclonedx-sbom-examples)$'
# ]

FILE_FILTERS = [
    r'^.*(bundled|contrib|demo|dependency|example|expect|external|fixture|inspector-scan|\/lib\/|libraries|libs\/|modules|package|packages\/|pcg|pcg-cpp|\/pkg\/|results|rtos|sample\/|samples\/|schema|template|test|third(-|_|\/|)party|vcpkg|worker(s|)\/).*$',
    r'^(lib\/).*$'
]

# SPDX SECTION
SPDX_YAML_FILTERS = [
    r'spdxVersion *: *(\"|)SPDX-',
    r'SPDXID *: *(\"|)SPDXRef-DOCUMENT'
]
SPDX_YAML_FILE_FILTERS = [
    r'^.*(\.yaml|\.yml)$'
]

SPDX_JSON_FILTERS = [
    r'\"SPDXVersion\" *: *\"SPDX-',
    r'\"SPDXID\" *: *\"SPDXRef-DOCUMENT\"'
]
SPDX_JSON_FILE_FILTERS = [
    r'^.*(\.json)$'
]

SPDX_XML_FILTERS = [
    r'<SPDXID> *SPDXRef-DOCUMENT *<\/SPDXID>',
]
SPDX_XML_FILE_FILTERS = [
    r'^.*(\.xml)$'
]

SPDX_RDF_FILTERS = [
    r'xmlns:spdx *= *(\"|)http(s|):\/\/spdx.org\/rdf\/terms'
]
SPDX_RDF_FILE_FILTERS = [
    r'^.*(\.rdf|\.xml)$'
]

SPDX_SPDX_FILTERS = [
    r'SPDXVersion(\"|\'|) *: *(\"|\'|)SPDX-',
    r'SPDXID(\"|\'|) *: *(\"|\'|)SPDXRef-DOCUMENT',
]
SPDX_SPDX_AND_FILTERS = [
    r'Relationship(\"|\'|) *:'
]
SPDX_SPDX_FILE_FILTERS = [
    r'^.*(\.spdx|(\.|)license)$'
]

SPDX_GENERIC_FILTERS = SPDX_SPDX_FILTERS
SPDX_GENERIC_FILE_FILTERS = [
    r'^.*(\.sbom|\.bom)$'
]

# CYCLONEDX SECTION
CYCLONEDX_XML_FILTERS = [
    r'xmlns *= *(\"|)http(s|):\/\/cyclonedx.org\/schema\/bom\/'
]
CYCLONEDX_XML_FILE_FILTERS = [
    r'^.*(\.xml|\.bom|\.sbom|\.cdx)$'
]


CYCLONEDX_JSON_FILTERS = [
    r'\"bomFormat\" *: *\"CycloneDX\"'
]
CYCLONEDX_JSON_FILE_FILTERS = [
    r'^.*(\.json|\.bom|\.sbom|\.cdx)$'
]

# Languages_according_to_TIOBE
TOP_20_LANGUAGES = [
    'Python', 'C++', 'Java', 'C', 'C#', 'JavaScript', 'VBA', 'VBScript', 'Go', 'SQL', 'Fortran',
    'Pascal', 'MATLAB', 'PHP', 'Rust', 'R', 'Ruby', 'Kotlin', 'COBOL', 'Swift'
]
GITHUB_POPULAR_LANGUAGES = [
    'C', 'C#', 'C++', 'CoffeeScript', 'CSS', 'Dart', 'DM', 'Go', 'Groovy', 'HTML', 'Java', 'JavaScript',
    'Kotlin', 'Objective-C', 'Perl', 'PHP', 'PowerShell', 'Python', 'Ruby', 'Rust', 'Scala', 'Shell', 'Swift',
    'TypeScript'
]

ARCHIVE_EXTENSIONS = [".zip", ".tar", ".tgz", ".7z", ".rar", ".gz", ".xz"]

def get_latest_data_folder(folder: str) -> str:
    # find the latest 'data_*' folder
    data_folders = [f for f in os.listdir(folder) if os.path.isdir(os.path.join(folder, f)) and f[:5] == 'data_']
    data_folders.sort(reverse=True)
    if len(data_folders) == 0:
        print("No data folders found.")
        return ''
    return str(os.path.join(folder, data_folders[0]))

def get_all_data_folders(folder: str) -> list[str]:
    # find the latest 'data_*' folder
    data_folders = [f for f in os.listdir(folder) if os.path.isdir(os.path.join(folder, f)) and f[:5] == 'data_']
    data_folders.sort(reverse=True)
    if len(data_folders) == 0:
        print("No data folders found.")
        return []
    return data_folders

def get_folder_size(folder: str) -> int:
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                total_size += os.path.getsize(fp)
            except FileNotFoundError:
                continue
    return total_size

def random_string(length: int) -> str:
    import random
    import string
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

async def unpack_archive(archive_path:str, unpacked_dir:str) -> bool:
    # get current unpack formats
    # add 7zip to the list of unpack formats
    # if 7zip is not in the list
    unpack_formats = await aioshutil.get_unpack_formats()
    if '7zip' not in [unpack_format[0] for unpack_format in unpack_formats]:
        # register shutil.unpack_archive function for 7zip archives
        await aioshutil.register_unpack_format('7zip', ['.7z'], unpack_7zarchive)

    # check if the asset is an archive
    archive_name = os.path.basename(archive_path)
    if archive_name.endswith(tuple(ARCHIVE_EXTENSIONS)):
        try:
            extension: str = archive_name.split('.')[-1]
            if extension.lower() == 'rar':
                patoolib.extract_archive(archive_path, outdir=unpacked_dir, verbosity=-1, interactive=False)
            else:
                await aioshutil.unpack_archive(archive_path, unpacked_dir)
        except ReadError:
            try:
                unpacked = False
                if zipfile.is_zipfile(archive_path):
                    with ZipFile(archive_path, 'r') as zip_ref:
                        zip_ref.extractall(unpacked_dir)
                        unpacked = True
                if tarfile.is_tarfile(archive_path):
                    with tarfile.open(archive_path, 'r') as tar_ref:
                        tar_ref.extractall(unpacked_dir)
                        unpacked = True
                if not unpacked:
                    print(f"Could not extract the archive: {archive_path}")
                    if not os.path.exists(unpacked_dir):
                        return False
            except Exception as e:
                print(f"Error: {e}")
                print(f"Could not extract the archive: {archive_path}")
                if not os.path.exists(unpacked_dir):
                    return False
        except UnsupportedCompressionMethodError as e:
            if "py7zr" in e.args[1]:
                # check if unpacked_dir exists
                # because sometimes this tool can extract at least some data
                if not os.path.exists(unpacked_dir):
                    return False
        except Exception as e:
            print(f"Error: {e}")
            print(f"Could not extract the archive: {archive_path}")
            if not os.path.exists(unpacked_dir):
                return False
        # check if unpacked_dir exists
        # because some archives may be empty
        if not os.path.exists(unpacked_dir):
            return False
        return True
    return False