import os

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
    "github.com/sonatype-nexus-community/cyclonedx-sbom-examples"
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
    r'^.*(bundled|contrib|demo|dependency|example|expect|external|fixture|inspector-scan|\/lib\/|libraries|libs\/|modules|package|packages\/|pcg|pcg-cpp|\/pkg\/|results|rtos|sample\/|samples\/|schema|template|test|third(-|_|\/|)party|vcpkg).*$',
    r'^(lib\/).*$'
]

# SPDX SECTION
SPDX_YAML_FILTERS = [
    r'spdxVersion *: *(\"|)SPDX-',
    r'SPDXID *: *(\"|)SPDXRef-DOCUMENT'
]
SPDX_YAML_FILE_FILTERS = [
    r'^.*(\.yaml)$'
]

SPDX_JSON_FILTERS = [
    r'\"SPDXVersion\" *: *\"SPDX-',
    r'\"SPDXID\" *: *\"SPDXRef-DOCUMENT\"'
]
SPDX_JSON_FILE_FILTERS = [
    r'^.*(\.json)$'
]

SPDX_SPDX_FILTERS = [
    r'SPDXVersion(\"|\'|) *: *(\"|\'|)SPDX-',
    r'SPDXID(\"|\'|) *: *(\"|\'|)SPDXRef-DOCUMENT',
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
    r'^.*(\.xml|\.bom|\.sbom)$'
]


CYCLONEDX_JSON_FILTERS = [
    r'\"bomFormat\" *: *\"CycloneDX\"'
]
CYCLONEDX_JSON_FILE_FILTERS = [
    r'^.*(\.json|\.bom|\.sbom)$'
]


def get_latest_data_folder(folder: str) -> str:
    # find the latest 'data_*' folder
    data_folders = [f for f in os.listdir(folder) if os.path.isdir(os.path.join(folder, f)) and f[:5] == 'data_']
    data_folders.sort(reverse=True)
    if len(data_folders) == 0:
        print("No data folders found.")
        return ''
    return str(os.path.join(folder, data_folders[0]))