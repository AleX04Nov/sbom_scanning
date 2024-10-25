import asyncio
import csv
import json
import os
import urllib.parse
import xmltodict
import yaml
from spdx_tools.spdx.parser.tagvalue.parser import Parser
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.model import Document
from license_expression import ExpressionParseError
from license_expression import LicenseExpression

import utils

data_folder = ''
sbom_folder = 'sbom_files'

csv_sbom_header = [
    'sbom_code',
    'name', 'URL', 'path', 'dependencies', 'licenses', 'critical',
    'high', 'medium', 'low', 'quality', 'format', 'version',
    'successfully_processed', 'sbomqs_processed', 'osv_processed', 'cyclonedx_processed',
    'sbom_utility_processed', 'pyspdxtools_processed', 'ntia_processed',
    'cyclonedx_res', 'sbom_utility_res', 'pyspdxtools_res', 'ntia_res', 'language'
]

csv_dependency_header = [
    'sbom_code',
    'name', 'version', 'location', 'licenses', 'CVEs', 'CWEs',
    'criticality', 'severity', 'relationships', 'relationship_types',
    'checksum', 'checksum_algo', 'ecosystem'
]
SEVERITY_MAP = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'MODERATE': 2,
    'LOW': 1
}
SEVERITY_REVERSE_MAP = {
    4: 'CRITICAL',
    3: 'HIGH',
    2: 'MEDIUM',
    1: 'LOW',
    0: 'NONE'
}


def purl_get_version(purl):
    version = purl.split(':')[1]
    # if there is @ in the name, leave right part
    if '@' in version:
        version = version.split('@')[-1]
    else:
        version = ''
    if '?' in version:
        version = version[:version.find('?')]
    return version


def purl_get_ecosystem(purl):
    ecosystem = purl.split(':')
    # if there is @ in the name, leave left part
    if '@' in ecosystem:
        ecosystem = ecosystem.split('@')[0]
    # detect first / and leave left part
    if '/' in ecosystem:
        ecosystem = ecosystem[:ecosystem.find('/')]
    else:
        ecosystem = ''
    return ecosystem


def purl_get_name(purl):
    name = purl.split(':')[1]
    # if there is @ in the name, leave left part
    if '@' in name:
        name = name.split('@')[0]
    # detect first / and leave right part
    if '/' in name:
        name = name[name.find('/')+1:]
    return name


def spdx_retrieve_license_list(license_str):
    licenses = []
    license_str = license_str.replace('(', '')
    license_str = license_str.replace(')', '')
    license_str = license_str.replace('AND', '')
    license_str = license_str.replace('OR', '')
    license_str = license_str.replace('WITH', '')
    license_str = license_str.replace('+', '')
    for license in license_str.split(' '):
        license = license.strip()
        if license:
            licenses.append(license)
    return list(set(licenses))


def osv_get_vulnerabilities(osv_file_path):
    packages_with_vulns = {}
    with open(osv_file_path, 'r') as f:
        try:
            osv_dict = json.load(f)
        except json.JSONDecodeError:
            return {}
    osv_results = osv_dict.get('results', [])
    for osv_result in osv_results:
        osv_packages = osv_result.get('packages', [])
        for osv_package in osv_packages:
            osv_package_info = osv_package.get('package', {})
            if not osv_package_info:
                continue
            package_name = osv_package_info.get('name', '')
            package_name = urllib.parse.unquote(package_name)
            package_version = osv_package_info.get('version', '')
            package_version = urllib.parse.unquote(package_version)
            package_ecosystem = osv_package_info.get('ecosystem', '')
            package_ecosystem = urllib.parse.unquote(package_ecosystem)
            if package_ecosystem == 'Maven':
                package_name = package_name.replace(':', '/')
            elif package_ecosystem == 'Alpine':
                package_name = 'alpine/' + package_name

            packages_with_vulns[f'{package_name}@{package_version}'] = {}
            package_with_vulns_dict = packages_with_vulns[f'{package_name}@{package_version}']
            package_with_vulns_dict['max_severity'] = 0
            package_with_vulns_dict['CVE'] = []
            package_with_vulns_dict['CWE'] = []
            package_with_vulns_dict['SEVERITY'] = []
            package_with_vulns_dict['SEVERITY_SCORE'] = ''

            package_vulnerabilities = osv_package.get('vulnerabilities', [])
            for package_vulnerability in package_vulnerabilities:
                severity_dict = package_vulnerability.get('severity', {})
                for severity_elem in severity_dict:
                    package_with_vulns_dict['SEVERITY_SCORE'] = severity_elem.get('score', '')
                    break

                vulnerability_database_specific = package_vulnerability.get('database_specific', {})
                if vulnerability_database_specific:
                    severity = vulnerability_database_specific.get('severity', '')
                    if severity:
                        severity = SEVERITY_MAP.get(severity, 0)
                        package_with_vulns_dict['SEVERITY'].append(severity)
                        if severity > package_with_vulns_dict['max_severity']:
                            package_with_vulns_dict['max_severity'] = severity
                    cwe_ids = vulnerability_database_specific.get('cwe_ids', [])
                    for cwe_id in cwe_ids:
                        package_with_vulns_dict['CWE'].append(cwe_id)
                cve_id = package_vulnerability.get('id', '')
                if 'CVE-' != cve_id[:4]:
                    cve_aliases = package_vulnerability.get('aliases', [])
                    for cve_alias in cve_aliases:
                        if 'CVE-' == cve_alias[:4]:
                            cve_id = cve_alias
                            break
                package_with_vulns_dict['CVE'].append(cve_id)
        # break as we should process only one sbom file per osv file
        break
    return packages_with_vulns


def sbomqs_get_quality(sbomqs_file_path):
    quality = 0.0
    with open(sbomqs_file_path, 'r') as f:
        sbomqs_data = json.load(f)
    sbomqs_files = sbomqs_data.get('files', [])
    for sbomqs_file in sbomqs_files:
        quality = sbomqs_file.get('avg_score', 0)
        quality = round(quality, 2)
        # break as we should process only one sbom file per sbomqs file
        break
    return quality


async def get_csv_from_cyclonedx_json(sbom, repo_name):
    sbom_code = sbom["file_name"]

    csv_sbom = []
    csv_dependency = []

    sbom_url = sbom["url"]
    sbom_path = sbom["path"]

    # get from dependencies
    sbom_dependencies_count = 0
    sbom_licenses_count = 0

    # get from osv file
    sbom_critical_vulns = 0
    sbom_high_vulns = 0
    sbom_medium_vulns = 0
    sbom_low_vulns = 0

    # get from sbomqs file
    sbom_quality = 0

    sbom_format = 'cyclonedx_json'
    sbom_version = ''

    sbom_successfully_processed = False
    sbom_sbomqs_processed = False
    sbom_osv_processed = False
    sbom_cyclonedx_processed = False
    sbom_sbom_utility_processed = False
    sbom_pyspdxtools_processed = False
    sbom_ntia_processed = False

    sbom_cyclonedx_res = False
    sbom_sbom_utility_res = False
    sbom_pyspdxtools_res = False
    sbom_ntia_res = False


    packages_with_vulns = {}
    if sbom.get('osv_file'):
        sbom_osv_processed = True
        osv_file_path = os.path.join(sbom_folder, sbom["osv_file"].split('/')[-1])
        packages_with_vulns = osv_get_vulnerabilities(osv_file_path)
        for package in packages_with_vulns:
            package_vulns = packages_with_vulns[package]
            for severity in package_vulns['SEVERITY']:
                if severity == 4:
                    sbom_critical_vulns += 1
                elif severity == 3:
                    sbom_high_vulns += 1
                elif severity == 2:
                    sbom_medium_vulns += 1
                elif severity == 1:
                    sbom_low_vulns += 1
            '''
            if package_vulns['max_severity'] == 4:
                sbom_critical_vulns += 1
            elif package_vulns['max_severity'] == 3:
                sbom_high_vulns += 1
            elif package_vulns['max_severity'] == 2:
                sbom_medium_vulns += 1
            elif package_vulns['max_severity'] == 1:
                sbom_low_vulns += 1
            '''

    if sbom.get('sbomqs_file'):
        sbom_sbomqs_processed = True
        sbomqs_file_path = os.path.join(sbom_folder, sbom["sbomqs_file"].split('/')[-1])
        sbom_quality = sbomqs_get_quality(sbomqs_file_path)

    if sbom.get('cyclonedx') is not None:
        sbom_cyclonedx_processed = True
        sbom_cyclonedx_res = sbom.get('cyclonedx')

    if sbom.get('sbom_utility') is not None:
        sbom_sbom_utility_processed = True
        sbom_sbom_utility_res = sbom.get('sbom_utility')

    if sbom.get('spdx_tool') is not None:
        sbom_pyspdxtools_processed = True
        sbom_pyspdxtools_res = sbom.get('pyspdxtools')

    if sbom.get('ntia_file'):
        sbom_ntia_processed = True
        with open(os.path.join(sbom_folder, sbom["ntia_file"]), 'r') as f:
            try:
                ntia_data = json.load(f)
                sbom_ntia_res = ntia_data.get('isNtiaConformant', False)
            except json.JSONDecodeError:
                sbom_ntia_res = False

    sbom_file_path = os.path.join(sbom_folder, sbom["file_name"])
    with open(sbom_file_path, 'r') as f:
        try:
            sbom_data = json.load(f)
        except json.JSONDecodeError:
            csv_sbom.append(sbom_code)
            csv_sbom.append(repo_name)
            csv_sbom.append(sbom_url)
            csv_sbom.append(sbom_path)
            csv_sbom.append(sbom_dependencies_count)
            csv_sbom.append(sbom_licenses_count)
            csv_sbom.append(sbom_critical_vulns)
            csv_sbom.append(sbom_high_vulns)
            csv_sbom.append(sbom_medium_vulns)
            csv_sbom.append(sbom_low_vulns)
            csv_sbom.append(sbom_quality)
            csv_sbom.append(sbom_format)
            csv_sbom.append(sbom_version)
            csv_sbom.append(sbom_successfully_processed)
            csv_sbom.append(sbom_sbomqs_processed)
            csv_sbom.append(sbom_osv_processed)
            csv_sbom.append(sbom_cyclonedx_processed)
            csv_sbom.append(sbom_sbom_utility_processed)
            csv_sbom.append(sbom_pyspdxtools_processed)
            csv_sbom.append(sbom_ntia_processed)
            csv_sbom.append(sbom_cyclonedx_res)
            csv_sbom.append(sbom_sbom_utility_res)
            csv_sbom.append(sbom_pyspdxtools_res)
            csv_sbom.append(sbom_ntia_res)
            return csv_sbom, []

    sbom_successfully_processed = True

    sbom_version = sbom_data.get("specVersion", '')

    found_vulns = False
    dependencies = sbom_data.get('components', [])
    sbom_dependencies_count = len(dependencies)
    if sbom_dependencies_count == 0:
        return [], []
    for dependency in dependencies:
        local_csv_dependency = []
        csv_licenses_list = []

        purl = ''
        ecosystem = ''
        version = ''

        if dependency.get('purl', ''):
            purl = urllib.parse.unquote(dependency['purl'])
            name = purl_get_name(purl)
            if name == '':
                name = dependency.get('name', '')
                name = urllib.parse.unquote(name)
            version = purl_get_version(purl)
            if version == '':
                version = dependency.get('version', '')
                version = urllib.parse.unquote(version)
            ecosystem = purl_get_ecosystem(purl)
        else:
            name = dependency.get('name', '')
            name = urllib.parse.unquote(name)
            version = dependency.get('version', '')
            version = urllib.parse.unquote(version)
        licenses = dependency.get('licenses', [])
        for dep_license in licenses:
            license_obj = dep_license.get('license', {})
            if license_obj:
                license_name = license_obj.get('name', '')
                if license_name:
                    csv_licenses_list.append(license_name)
                else:
                    license_name = license_obj.get('id', '')
                    if license_name:
                        csv_licenses_list.append(license_name)
        evidence = dependency.get('evidence', {})
        licenses = evidence.get('licenses', [])
        for dep_license in licenses:
            license_obj = dep_license.get('license', {})
            if license_obj:
                license_name = license_obj.get('name', '')
                if license_name:
                    csv_licenses_list.append(license_name)
                else:
                    license_name = license_obj.get('id', '')
                    if license_name:
                        csv_licenses_list.append(license_name)
        sbom_licenses_count += len(csv_licenses_list)

        cves = []
        cwes = []
        criticality = ''
        severity = []
        dependency_vulns = packages_with_vulns.get(f'{name}@{version}', {})
        if not dependency_vulns:
            dependency_vulns = packages_with_vulns.get(f'{name}@', {})
        if dependency_vulns:
            found_vulns = True
            cves = dependency_vulns.get('CVE', [])
            cwes = dependency_vulns.get('CWE', [])
            criticality = dependency_vulns.get('SEVERITY_SCORE', '')
            severity = dependency_vulns.get('SEVERITY', [])
            for severity_index in range(len(severity)):
                severity[severity_index] = SEVERITY_REVERSE_MAP.get(severity[severity_index], 'NONE')

        # no such fields in CycloneDX
        relationships = []
        relationship_types = []

        checksum_list = dependency.get('hashes', [])
        checksum = ''
        checksum_algo = ''
        # get the first one
        for checksum in checksum_list:
            checksum_algo = checksum.get('alg', '')
            checksum = checksum.get('content', '')
            break


        local_csv_dependency.append(sbom_code)
        local_csv_dependency.append(name)
        local_csv_dependency.append(version)
        local_csv_dependency.append(purl)
        local_csv_dependency.append('|'.join(csv_licenses_list))
        local_csv_dependency.append('|'.join(cves))
        local_csv_dependency.append('|'.join(cwes))
        local_csv_dependency.append(criticality)
        local_csv_dependency.append('|'.join(severity))
        local_csv_dependency.append('|'.join(relationships))
        local_csv_dependency.append('|'.join(relationship_types))
        local_csv_dependency.append(checksum)
        local_csv_dependency.append(checksum_algo)
        local_csv_dependency.append(ecosystem)
        csv_dependency.append(local_csv_dependency)

    if not found_vulns and len(packages_with_vulns) > 0:
        print(f'No vulnerabilities found for {sbom_code}')

    csv_sbom.append(sbom_code)
    csv_sbom.append(repo_name)
    csv_sbom.append(sbom_url)
    csv_sbom.append(sbom_path)
    csv_sbom.append(sbom_dependencies_count)
    csv_sbom.append(sbom_licenses_count)
    csv_sbom.append(sbom_critical_vulns)
    csv_sbom.append(sbom_high_vulns)
    csv_sbom.append(sbom_medium_vulns)
    csv_sbom.append(sbom_low_vulns)
    csv_sbom.append(sbom_quality)
    csv_sbom.append(sbom_format)
    csv_sbom.append(sbom_version)
    csv_sbom.append(sbom_successfully_processed)
    csv_sbom.append(sbom_sbomqs_processed)
    csv_sbom.append(sbom_osv_processed)
    csv_sbom.append(sbom_cyclonedx_processed)
    csv_sbom.append(sbom_sbom_utility_processed)
    csv_sbom.append(sbom_pyspdxtools_processed)
    csv_sbom.append(sbom_ntia_processed)
    csv_sbom.append(sbom_cyclonedx_res)
    csv_sbom.append(sbom_sbom_utility_res)
    csv_sbom.append(sbom_pyspdxtools_res)
    csv_sbom.append(sbom_ntia_res)

    return csv_sbom, csv_dependency


async def get_csv_from_cyclonedx_xml(sbom, repo_name):
    sbom_code = sbom["file_name"]

    csv_sbom = []
    csv_dependency = []

    sbom_url = sbom["url"]
    sbom_path = sbom["path"]

    # get from dependencies
    sbom_dependencies_count = 0
    sbom_licenses_count = 0

    # get from osv file
    sbom_critical_vulns = 0
    sbom_high_vulns = 0
    sbom_medium_vulns = 0
    sbom_low_vulns = 0

    # get from sbomqs file
    sbom_quality = 0

    sbom_format = 'cyclnedx_xml'
    sbom_version = ''

    sbom_successfully_processed = False
    sbom_sbomqs_processed = False
    sbom_osv_processed = False
    sbom_cyclonedx_processed = False
    sbom_sbom_utility_processed = False
    sbom_pyspdxtools_processed = False
    sbom_ntia_processed = False

    sbom_cyclonedx_res = False
    sbom_sbom_utility_res = False
    sbom_pyspdxtools_res = False
    sbom_ntia_res = False

    packages_with_vulns = {}
    if sbom.get('osv_file'):
        sbom_osv_processed = True
        osv_file_path = os.path.join(sbom_folder, sbom["osv_file"].split('/')[-1])
        packages_with_vulns = osv_get_vulnerabilities(osv_file_path)
        for package in packages_with_vulns:
            package_vulns = packages_with_vulns[package]
            for severity in package_vulns['SEVERITY']:
                if severity == 4:
                    sbom_critical_vulns += 1
                elif severity == 3:
                    sbom_high_vulns += 1
                elif severity == 2:
                    sbom_medium_vulns += 1
                elif severity == 1:
                    sbom_low_vulns += 1
            '''
            if package_vulns['max_severity'] == 4:
                sbom_critical_vulns += 1
            elif package_vulns['max_severity'] == 3:
                sbom_high_vulns += 1
            elif package_vulns['max_severity'] == 2:
                sbom_medium_vulns += 1
            elif package_vulns['max_severity'] == 1:
                sbom_low_vulns += 1
            '''

    if sbom.get('sbomqs_file'):
        sbomqs_file_path = os.path.join(sbom_folder, sbom["sbomqs_file"].split('/')[-1])
        sbom_quality = sbomqs_get_quality(sbomqs_file_path)

    if sbom.get('cyclonedx') is not None:
        sbom_cyclonedx_processed = True
        sbom_cyclonedx_res = sbom.get('cyclonedx')

    if sbom.get('sbom_utility') is not None:
        sbom_sbom_utility_processed = True
        sbom_sbom_utility_res = sbom.get('sbom_utility')

    if sbom.get('spdx_tool') is not None:
        sbom_pyspdxtools_processed = True
        sbom_pyspdxtools_res = sbom.get('pyspdxtools')

    if sbom.get('ntia_file'):
        sbom_ntia_processed = True
        with open(os.path.join(sbom_folder, sbom["ntia_file"]), 'r') as f:
            try:
                ntia_data = json.load(f)
                sbom_ntia_res = ntia_data.get('isNtiaConformant', False)
            except json.JSONDecodeError:
                sbom_ntia_res = False

    sbom_file_path = os.path.join(sbom_folder, sbom["file_name"])
    with open(sbom_file_path, 'r') as f:
        xml_text = f.read()
        # skip to xml
        # lib cant process prexml comments
        xml_text = xml_text[xml_text.find('<?xml'):]
        sbom_data = xmltodict.parse(xml_text)
        sbom_data = sbom_data.get('bom', {})

    sbom_successfully_processed = True

    sbom_version = sbom_data.get('@xmlns', '').split('/')[-1]

    found_vulns = False
    dependencies = sbom_data.get('components', {})
    dependencies = dependencies.get('component', [])
    # check dependencies type
    if isinstance(dependencies, dict):
        dependencies = [dependencies]
    sbom_dependencies_count = len(dependencies)
    if sbom_dependencies_count == 0:
        return [], []
    for dependency in dependencies:
        local_csv_dependency = []
        csv_licenses_list = []

        purl = ''
        ecosystem = ''
        version = ''

        purl = dependency.get('purl', '')
        if purl and purl != '':
            purl = urllib.parse.unquote(dependency['purl'])
            name = purl_get_name(purl)
            if name == '':
                name = dependency.get('name', '')
                if name is None:
                    name = ''
                name = urllib.parse.unquote(name)
            version = purl_get_version(purl)
            if version == '':
                version = dependency.get('version', '')
                if version is None:
                    version = ''
                version = urllib.parse.unquote(version)
            ecosystem = purl_get_ecosystem(purl)
        else:
            name = dependency.get('name', '')
            if name is None:
                name = ''
            name = urllib.parse.unquote(name)
            version = dependency.get('version', '')
            if version is None:
                version = ''
            version = urllib.parse.unquote(version)
        licenses = dependency.get('licenses', {})
        if isinstance(licenses, dict):
            licenses = [licenses]
        if not isinstance(licenses, list):
            licenses = []
        for dep_license in licenses:
            license_obj = dep_license.get('license', {})
            if isinstance(license_obj, list):
                for license_in_list in license_obj:
                    license_name = license_in_list.get('id', '')
                    if license_name:
                        csv_licenses_list.append(license_name)
                    else:
                        license_name = license_in_list.get('name', '')
                        if license_name:
                            csv_licenses_list.append(license_name)
                        else:
                            license_name = license_in_list.get('expression', '')
                            if license_name:
                                csv_licenses_list.append(license_name)
                break
            license_name = license_obj.get('id', '')
            if license_name:
                csv_licenses_list.append(license_name)
            else:
                license_name = license_obj.get('name', '')
                if license_name:
                    csv_licenses_list.append(license_name)
                else:
                    license_name = license_obj.get('expression', '')
                    if license_name:
                        csv_licenses_list.append(license_name)
        evidence = dependency.get('evidence', {})
        licenses = evidence.get('licenses', {})
        if isinstance(licenses, dict):
            licenses = [licenses]
        if not isinstance(licenses, list):
            licenses = []
        for dep_license in licenses:
            license_obj = dep_license.get('license', {})
            if isinstance(license_obj, list):
                for license_in_list in license_obj:
                    license_name = license_in_list.get('id', '')
                    if license_name:
                        csv_licenses_list.append(license_name)
                    else:
                        license_name = license_in_list.get('name', '')
                        if license_name:
                            csv_licenses_list.append(license_name)
                break
            license_name = license_obj.get('id', '')
            if license_name:
                csv_licenses_list.append(license_name)
            else:
                license_name = license_obj.get('name', '')
                if license_name:
                    csv_licenses_list.append(license_name)
        sbom_licenses_count += len(csv_licenses_list)

        cves = []
        cwes = []
        criticality = ''
        severity = []
        dependency_vulns = packages_with_vulns.get(f'{name}@{version}', {})
        if not dependency_vulns:
            dependency_vulns = packages_with_vulns.get(f'{name}@', {})
        if dependency_vulns:
            found_vulns = True
            cves = dependency_vulns.get('CVE', [])
            cwes = dependency_vulns.get('CWE', [])
            criticality = dependency_vulns.get('SEVERITY_SCORE', '')
            severity = dependency_vulns.get('SEVERITY', [])
            for severity_index in range(len(severity)):
                severity[severity_index] = SEVERITY_REVERSE_MAP.get(severity[severity_index], 'NONE')

        # no such fields in CycloneDX
        relationships = []
        relationship_types = []

        checksum_list = dependency.get('hashes', {})
        checksum_list = checksum_list.get('hash', [])
        if isinstance(checksum_list, dict):
            checksum_list = [checksum_list]
        checksum = ''
        checksum_algo = ''
        # get the first one
        for checksum in checksum_list:
            checksum_algo = checksum.get('@alg', '')
            checksum = checksum.get('#text', '')
            break


        local_csv_dependency.append(sbom_code)
        local_csv_dependency.append(name)
        local_csv_dependency.append(version)
        local_csv_dependency.append(purl)
        local_csv_dependency.append('|'.join(csv_licenses_list))
        local_csv_dependency.append('|'.join(cves))
        local_csv_dependency.append('|'.join(cwes))
        local_csv_dependency.append(criticality)
        local_csv_dependency.append('|'.join(severity))
        local_csv_dependency.append('|'.join(relationships))
        local_csv_dependency.append('|'.join(relationship_types))
        local_csv_dependency.append(checksum)
        local_csv_dependency.append(checksum_algo)
        local_csv_dependency.append(ecosystem)
        csv_dependency.append(local_csv_dependency)

    if not found_vulns and len(packages_with_vulns) > 0:
        print(f'No vulnerabilities found for {sbom_code}')

    csv_sbom.append(sbom_code)
    csv_sbom.append(repo_name)
    csv_sbom.append(sbom_url)
    csv_sbom.append(sbom_path)
    csv_sbom.append(sbom_dependencies_count)
    csv_sbom.append(sbom_licenses_count)
    csv_sbom.append(sbom_critical_vulns)
    csv_sbom.append(sbom_high_vulns)
    csv_sbom.append(sbom_medium_vulns)
    csv_sbom.append(sbom_low_vulns)
    csv_sbom.append(sbom_quality)
    csv_sbom.append(sbom_format)
    csv_sbom.append(sbom_version)
    csv_sbom.append(sbom_successfully_processed)
    csv_sbom.append(sbom_sbomqs_processed)
    csv_sbom.append(sbom_osv_processed)
    csv_sbom.append(sbom_cyclonedx_processed)
    csv_sbom.append(sbom_sbom_utility_processed)
    csv_sbom.append(sbom_pyspdxtools_processed)
    csv_sbom.append(sbom_ntia_processed)
    csv_sbom.append(sbom_cyclonedx_res)
    csv_sbom.append(sbom_sbom_utility_res)
    csv_sbom.append(sbom_pyspdxtools_res)
    csv_sbom.append(sbom_ntia_res)

    return csv_sbom, csv_dependency


async def get_csv_from_spdx_rdf(sbom, repo_name):
    sbom_code = sbom["file_name"]

    csv_sbom = []
    csv_dependency = []

    sbom_url = sbom["url"]
    sbom_path = sbom["path"]

    # get from dependencies
    sbom_dependencies_count = 0
    sbom_licenses_count = 0

    # get from osv file
    sbom_critical_vulns = 0
    sbom_high_vulns = 0
    sbom_medium_vulns = 0
    sbom_low_vulns = 0

    # get from sbomqs file
    sbom_quality = 0

    sbom_format = 'spdx_rdf'
    sbom_version = ''

    sbom_successfully_processed = False
    sbom_sbomqs_processed = False
    sbom_osv_processed = False
    sbom_cyclonedx_processed = False
    sbom_sbom_utility_processed = False
    sbom_pyspdxtools_processed = False
    sbom_ntia_processed = False

    sbom_cyclonedx_res = False
    sbom_sbom_utility_res = False
    sbom_pyspdxtools_res = False
    sbom_ntia_res = False

    packages_with_vulns = {}
    if sbom.get('osv_file'):
        sbom_osv_processed = True
        osv_file_path = os.path.join(sbom_folder, sbom["osv_file"].split('/')[-1])
        packages_with_vulns = osv_get_vulnerabilities(osv_file_path)
        for package in packages_with_vulns:
            package_vulns = packages_with_vulns[package]
            for severity in package_vulns['SEVERITY']:
                if severity == 4:
                    sbom_critical_vulns += 1
                elif severity == 3:
                    sbom_high_vulns += 1
                elif severity == 2:
                    sbom_medium_vulns += 1
                elif severity == 1:
                    sbom_low_vulns += 1
            '''
            if package_vulns['max_severity'] == 4:
                sbom_critical_vulns += 1
            elif package_vulns['max_severity'] == 3:
                sbom_high_vulns += 1
            elif package_vulns['max_severity'] == 2:
                sbom_medium_vulns += 1
            elif package_vulns['max_severity'] == 1:
                sbom_low_vulns += 1
            '''

    if sbom.get('sbomqs_file'):
        sbomqs_file_path = os.path.join(sbom_folder, sbom["sbomqs_file"].split('/')[-1])
        sbom_quality = sbomqs_get_quality(sbomqs_file_path)

    if sbom.get('cyclonedx') is not None:
        sbom_cyclonedx_processed = True
        sbom_cyclonedx_res = sbom.get('cyclonedx')

    if sbom.get('sbom_utility') is not None:
        sbom_sbom_utility_processed = True
        sbom_sbom_utility_res = sbom.get('sbom_utility')

    if sbom.get('spdx_tool') is not None:
        sbom_pyspdxtools_processed = True
        sbom_pyspdxtools_res = sbom.get('pyspdxtools')

    if sbom.get('ntia_file'):
        sbom_ntia_processed = True
        with open(os.path.join(sbom_folder, sbom["ntia_file"]), 'r') as f:
            try:
                ntia_data = json.load(f)
                sbom_ntia_res = ntia_data.get('isNtiaConformant', False)
            except json.JSONDecodeError:
                sbom_ntia_res = False

    sbom_file_path = os.path.join(sbom_folder, sbom["file_name"])
    with open(sbom_file_path, 'r') as f:
        csv_sbom.append(sbom_code)
        csv_sbom.append(repo_name)
        csv_sbom.append(sbom_url)
        csv_sbom.append(sbom_path)
        csv_sbom.append(sbom_dependencies_count)
        csv_sbom.append(sbom_licenses_count)
        csv_sbom.append(sbom_critical_vulns)
        csv_sbom.append(sbom_high_vulns)
        csv_sbom.append(sbom_medium_vulns)
        csv_sbom.append(sbom_low_vulns)
        csv_sbom.append(sbom_quality)
        csv_sbom.append(sbom_format)
        csv_sbom.append(sbom_version)
        csv_sbom.append(sbom_successfully_processed)
        csv_sbom.append(sbom_sbomqs_processed)
        csv_sbom.append(sbom_osv_processed)
        csv_sbom.append(sbom_cyclonedx_processed)
        csv_sbom.append(sbom_sbom_utility_processed)
        csv_sbom.append(sbom_pyspdxtools_processed)
        csv_sbom.append(sbom_ntia_processed)
        csv_sbom.append(sbom_cyclonedx_res)
        csv_sbom.append(sbom_sbom_utility_res)
        csv_sbom.append(sbom_pyspdxtools_res)
        csv_sbom.append(sbom_ntia_res)
        return csv_sbom, []

    sbom_successfully_processed = True

    sbom_version = sbom_data.get('@xmlns', '').split('/')[-1]

    found_vulns = False
    dependencies = sbom_data.get('components', {})
    dependencies = dependencies.get('component', [])
    # check dependencies type
    if isinstance(dependencies, dict):
        dependencies = [dependencies]
    sbom_dependencies_count = len(dependencies)
    if sbom_dependencies_count == 0:
        return [], []
    for dependency in dependencies:
        local_csv_dependency = []
        csv_licenses_list = []

        purl = ''
        ecosystem = ''
        version = ''

        purl = dependency.get('purl', '')
        if purl and purl != '':
            purl = urllib.parse.unquote(dependency['purl'])
            name = purl_get_name(purl)
            if name == '':
                name = dependency.get('name', '')
                if name is None:
                    name = ''
                name = urllib.parse.unquote(name)
            version = purl_get_version(purl)
            if version == '':
                version = dependency.get('version', '')
                if version is None:
                    version = ''
                version = urllib.parse.unquote(version)
            ecosystem = purl_get_ecosystem(purl)
        else:
            name = dependency.get('name', '')
            if name is None:
                name = ''
            name = urllib.parse.unquote(name)
            version = dependency.get('version', '')
            if version is None:
                version = ''
            version = urllib.parse.unquote(version)
        licenses = dependency.get('licenses', {})
        if isinstance(licenses, dict):
            licenses = [licenses]
        if not isinstance(licenses, list):
            licenses = []
        for dep_license in licenses:
            license_obj = dep_license.get('license', {})
            if isinstance(license_obj, list):
                for license_in_list in license_obj:
                    license_name = license_in_list.get('id', '')
                    if license_name:
                        csv_licenses_list.append(license_name)
                break
            license_name = license_obj.get('id', '')
            if license_name:
                csv_licenses_list.append(license_name)
        sbom_licenses_count += len(csv_licenses_list)

        cves = []
        cwes = []
        criticality = ''
        severity = []
        dependency_vulns = packages_with_vulns.get(f'{name}@{version}', {})
        if not dependency_vulns:
            dependency_vulns = packages_with_vulns.get(f'{name}@', {})
        if dependency_vulns:
            found_vulns = True
            cves = dependency_vulns.get('CVE', [])
            cwes = dependency_vulns.get('CWE', [])
            criticality = dependency_vulns.get('SEVERITY_SCORE', '')
            severity = dependency_vulns.get('SEVERITY', [])
            for severity_index in range(len(severity)):
                severity[severity_index] = SEVERITY_REVERSE_MAP.get(severity[severity_index], 'NONE')

        # no such fields in CycloneDX
        relationships = []
        relationship_types = []

        checksum_list = dependency.get('hashes', {})
        checksum_list = checksum_list.get('hash', [])
        if isinstance(checksum_list, dict):
            checksum_list = [checksum_list]
        checksum = ''
        checksum_algo = ''
        # get the first one
        for checksum in checksum_list:
            checksum_algo = checksum.get('@alg', '')
            checksum = checksum.get('#text', '')
            break


        local_csv_dependency.append(sbom_code)
        local_csv_dependency.append(name)
        local_csv_dependency.append(version)
        local_csv_dependency.append(purl)
        local_csv_dependency.append('|'.join(csv_licenses_list))
        local_csv_dependency.append('|'.join(cves))
        local_csv_dependency.append('|'.join(cwes))
        local_csv_dependency.append(criticality)
        local_csv_dependency.append('|'.join(severity))
        local_csv_dependency.append('|'.join(relationships))
        local_csv_dependency.append('|'.join(relationship_types))
        local_csv_dependency.append(checksum)
        local_csv_dependency.append(checksum_algo)
        local_csv_dependency.append(ecosystem)
        csv_dependency.append(local_csv_dependency)

    if not found_vulns and len(packages_with_vulns) > 0:
        print(f'No vulnerabilities found for {sbom_code}')

    csv_sbom.append(sbom_code)
    csv_sbom.append(repo_name)
    csv_sbom.append(sbom_url)
    csv_sbom.append(sbom_path)
    csv_sbom.append(sbom_dependencies_count)
    csv_sbom.append(sbom_licenses_count)
    csv_sbom.append(sbom_critical_vulns)
    csv_sbom.append(sbom_high_vulns)
    csv_sbom.append(sbom_medium_vulns)
    csv_sbom.append(sbom_low_vulns)
    csv_sbom.append(sbom_quality)
    csv_sbom.append(sbom_format)
    csv_sbom.append(sbom_version)
    csv_sbom.append(sbom_successfully_processed)
    csv_sbom.append(sbom_sbomqs_processed)
    csv_sbom.append(sbom_osv_processed)
    csv_sbom.append(sbom_cyclonedx_processed)
    csv_sbom.append(sbom_sbom_utility_processed)
    csv_sbom.append(sbom_pyspdxtools_processed)
    csv_sbom.append(sbom_ntia_processed)
    csv_sbom.append(sbom_cyclonedx_res)
    csv_sbom.append(sbom_sbom_utility_res)
    csv_sbom.append(sbom_pyspdxtools_res)
    csv_sbom.append(sbom_ntia_res)

    return csv_sbom, csv_dependency


async def get_csv_from_spdx_json(sbom, repo_name):
    sbom_code = sbom["file_name"]

    csv_sbom = []
    csv_dependency = []

    sbom_url = sbom["url"]
    sbom_path = sbom["path"]

    # get from dependencies
    sbom_dependencies_count = 0
    sbom_licenses_count = 0

    # get from osv file
    sbom_critical_vulns = 0
    sbom_high_vulns = 0
    sbom_medium_vulns = 0
    sbom_low_vulns = 0

    # get from sbomqs file
    sbom_quality = 0

    sbom_format = 'spdx_json'
    sbom_version = ''

    sbom_successfully_processed = False
    sbom_sbomqs_processed = False
    sbom_osv_processed = False
    sbom_cyclonedx_processed = False
    sbom_sbom_utility_processed = False
    sbom_pyspdxtools_processed = False
    sbom_ntia_processed = False

    sbom_cyclonedx_res = False
    sbom_sbom_utility_res = False
    sbom_pyspdxtools_res = False
    sbom_ntia_res = False

    packages_with_vulns = {}
    if sbom.get('osv_file'):
        sbom_osv_processed = True
        osv_file_path = os.path.join(sbom_folder, sbom["osv_file"].split('/')[-1])
        packages_with_vulns = osv_get_vulnerabilities(osv_file_path)
        for package in packages_with_vulns:
            package_vulns = packages_with_vulns[package]
            for severity in package_vulns['SEVERITY']:
                if severity == 4:
                    sbom_critical_vulns += 1
                elif severity == 3:
                    sbom_high_vulns += 1
                elif severity == 2:
                    sbom_medium_vulns += 1
                elif severity == 1:
                    sbom_low_vulns += 1
            '''
            if package_vulns['max_severity'] == 4:
                sbom_critical_vulns += 1
            elif package_vulns['max_severity'] == 3:
                sbom_high_vulns += 1
            elif package_vulns['max_severity'] == 2:
                sbom_medium_vulns += 1
            elif package_vulns['max_severity'] == 1:
                sbom_low_vulns += 1
            '''

    if sbom.get('sbomqs_file'):
        sbomqs_file_path = os.path.join(sbom_folder, sbom["sbomqs_file"].split('/')[-1])
        sbom_quality = sbomqs_get_quality(sbomqs_file_path)

    if sbom.get('cyclonedx') is not None:
        sbom_cyclonedx_processed = True
        sbom_cyclonedx_res = sbom.get('cyclonedx')

    if sbom.get('sbom_utility') is not None:
        sbom_sbom_utility_processed = True
        sbom_sbom_utility_res = sbom.get('sbom_utility')

    if sbom.get('spdx_tool') is not None:
        sbom_pyspdxtools_processed = True
        sbom_pyspdxtools_res = sbom.get('pyspdxtools')

    if sbom.get('ntia_file'):
        sbom_ntia_processed = True
        with open(os.path.join(sbom_folder, sbom["ntia_file"]), 'r') as f:
            try:
                ntia_data = json.load(f)
                sbom_ntia_res = ntia_data.get('isNtiaConformant', False)
            except json.JSONDecodeError:
                sbom_ntia_res = False

    sbom_file_path = os.path.join(sbom_folder, sbom["file_name"])
    with open(sbom_file_path, 'r') as f:
        try:
            sbom_data = json.load(f)
        except json.JSONDecodeError:
            csv_sbom.append(sbom_code)
            csv_sbom.append(repo_name)
            csv_sbom.append(sbom_url)
            csv_sbom.append(sbom_path)
            csv_sbom.append(sbom_dependencies_count)
            csv_sbom.append(sbom_licenses_count)
            csv_sbom.append(sbom_critical_vulns)
            csv_sbom.append(sbom_high_vulns)
            csv_sbom.append(sbom_medium_vulns)
            csv_sbom.append(sbom_low_vulns)
            csv_sbom.append(sbom_quality)
            csv_sbom.append(sbom_format)
            csv_sbom.append(sbom_version)
            csv_sbom.append(sbom_successfully_processed)
            csv_sbom.append(sbom_sbomqs_processed)
            csv_sbom.append(sbom_osv_processed)
            csv_sbom.append(sbom_cyclonedx_processed)
            csv_sbom.append(sbom_sbom_utility_processed)
            csv_sbom.append(sbom_pyspdxtools_processed)
            csv_sbom.append(sbom_ntia_processed)
            csv_sbom.append(sbom_cyclonedx_res)
            csv_sbom.append(sbom_sbom_utility_res)
            csv_sbom.append(sbom_pyspdxtools_res)
            csv_sbom.append(sbom_ntia_res)
            return csv_sbom, []

    sbom_successfully_processed = True

    relationships = sbom_data.get('relationships', [])
    # licensing_info = sbom_data.get('licensingInfo', [])

    sbom_version = sbom_data.get('spdxVersion', '')

    found_vulns = False
    dependencies = sbom_data.get('packages', [])
    sbom_dependencies_count = len(dependencies)
    if sbom_dependencies_count == 0:
        return [], []
    for dependency in dependencies:
        local_csv_dependency = []
        csv_licenses_list = []

        purl = ''
        ecosystem = ''
        spdxid = dependency.get('SPDXID', None)
        version = ''

        # get purl
        external_refs = dependency.get('externalRefs', [])
        for external_ref in external_refs:
            if external_ref.get('referenceType', '') == 'purl':
                purl = external_ref.get('referenceLocator', '')
                break

        if purl:
            purl = urllib.parse.unquote(purl)
            name = purl_get_name(purl)
            if name == '':
                name = dependency.get('name', '')
                name = urllib.parse.unquote(name)
            version = purl_get_version(purl)
            if version == '':
                version = dependency.get('versionInfo', '')
                version = urllib.parse.unquote(version)
            ecosystem = purl_get_ecosystem(purl)
        else:
            name = dependency.get('name', '')
            name = urllib.parse.unquote(name)
            version = dependency.get('version', '')
            version = urllib.parse.unquote(version)

        # add licenses
        license_declared = dependency.get('licenseDeclared', '')
        license_concluded = dependency.get('licenseConcluded', '')
        if license_declared == 'NOASSERTION':
            license_declared = ''
        if license_concluded == 'NOASSERTION':
            license_concluded = ''
        license_declared = spdx_retrieve_license_list(license_declared)
        license_concluded = spdx_retrieve_license_list(license_concluded)
        if license_declared:
            csv_licenses_list.extend(license_declared)
        elif license_concluded:
            csv_licenses_list.extend(license_concluded)
        csv_licenses_list = list(set(csv_licenses_list))
        sbom_licenses_count += len(csv_licenses_list)

        '''
        # get licenses from licensingInfo
        for license_index in range(len(csv_licenses_list)):
            license_enc = csv_licenses_list[license_index]
            for licensing_info_elem in licensing_info:
                if licensing_info_elem.get('licenseId', '') == license_enc:
                    csv_licenses_list[license_index] = licensing_info_elem.get('extractedText', '')
        '''

        cves = []
        cwes = []
        criticality = ''
        severity = []
        dependency_vulns = packages_with_vulns.get(f'{name}@{version}', {})
        if not dependency_vulns:
            dependency_vulns = packages_with_vulns.get(f'{name}@', {})
        if dependency_vulns:
            found_vulns = True
            cves = dependency_vulns.get('CVE', [])
            cwes = dependency_vulns.get('CWE', [])
            criticality = dependency_vulns.get('SEVERITY_SCORE', '')
            severity = dependency_vulns.get('SEVERITY', [])
            for severity_index in range(len(severity)):
                severity[severity_index] = SEVERITY_REVERSE_MAP.get(severity[severity_index], 'NONE')

        # do relationships
        dep_relationships = []
        dep_relationship_types = []
        for relationship in relationships:
            if relationship.get('spdxElementId', '') == spdxid:
                dep_relationships.append(relationship.get('relatedSpdxElement', ''))
                dep_relationship_types.append(relationship.get('relationshipType', ''))

        checksum_list = dependency.get('checksums', [])
        checksum = ''
        checksum_algo = ''
        # get the first one
        for checksum in checksum_list:
            checksum_algo = checksum.get('algorithm', '')
            checksum = checksum.get('checksumValue', '')
            break

        local_csv_dependency.append(sbom_code)
        local_csv_dependency.append(name)
        local_csv_dependency.append(version)
        local_csv_dependency.append(purl)
        local_csv_dependency.append('|'.join(csv_licenses_list))
        local_csv_dependency.append('|'.join(cves))
        local_csv_dependency.append('|'.join(cwes))
        local_csv_dependency.append(criticality)
        local_csv_dependency.append('|'.join(severity))
        local_csv_dependency.append('|'.join(dep_relationships))
        local_csv_dependency.append('|'.join(dep_relationship_types))
        local_csv_dependency.append(checksum)
        local_csv_dependency.append(checksum_algo)
        local_csv_dependency.append(ecosystem)
        csv_dependency.append(local_csv_dependency)

    if not found_vulns and len(packages_with_vulns) > 0:
        print(f'No vulnerabilities found for {sbom_code}')

    csv_sbom.append(sbom_code)
    csv_sbom.append(repo_name)
    csv_sbom.append(sbom_url)
    csv_sbom.append(sbom_path)
    csv_sbom.append(sbom_dependencies_count)
    csv_sbom.append(sbom_licenses_count)
    csv_sbom.append(sbom_critical_vulns)
    csv_sbom.append(sbom_high_vulns)
    csv_sbom.append(sbom_medium_vulns)
    csv_sbom.append(sbom_low_vulns)
    csv_sbom.append(sbom_quality)
    csv_sbom.append(sbom_format)
    csv_sbom.append(sbom_version)
    csv_sbom.append(sbom_successfully_processed)
    csv_sbom.append(sbom_sbomqs_processed)
    csv_sbom.append(sbom_osv_processed)
    csv_sbom.append(sbom_cyclonedx_processed)
    csv_sbom.append(sbom_sbom_utility_processed)
    csv_sbom.append(sbom_pyspdxtools_processed)
    csv_sbom.append(sbom_ntia_processed)
    csv_sbom.append(sbom_cyclonedx_res)
    csv_sbom.append(sbom_sbom_utility_res)
    csv_sbom.append(sbom_pyspdxtools_res)
    csv_sbom.append(sbom_ntia_res)

    return csv_sbom, csv_dependency


async def get_csv_from_spdx_yaml(sbom, repo_name):
    sbom_code = sbom["file_name"]

    csv_sbom = []
    csv_dependency = []

    sbom_url = sbom["url"]
    sbom_path = sbom["path"]

    # get from dependencies
    sbom_dependencies_count = 0
    sbom_licenses_count = 0

    # get from osv file
    sbom_critical_vulns = 0
    sbom_high_vulns = 0
    sbom_medium_vulns = 0
    sbom_low_vulns = 0

    # get from sbomqs file
    sbom_quality = 0

    sbom_format = 'spdx_yaml'
    sbom_version = ''

    sbom_successfully_processed = False
    sbom_sbomqs_processed = False
    sbom_osv_processed = False
    sbom_cyclonedx_processed = False
    sbom_sbom_utility_processed = False
    sbom_pyspdxtools_processed = False
    sbom_ntia_processed = False

    sbom_cyclonedx_res = False
    sbom_sbom_utility_res = False
    sbom_pyspdxtools_res = False
    sbom_ntia_res = False

    packages_with_vulns = {}
    if sbom.get('osv_file'):
        sbom_osv_processed = True
        osv_file_path = os.path.join(sbom_folder, sbom["osv_file"].split('/')[-1])
        packages_with_vulns = osv_get_vulnerabilities(osv_file_path)
        for package in packages_with_vulns:
            package_vulns = packages_with_vulns[package]
            for severity in package_vulns['SEVERITY']:
                if severity == 4:
                    sbom_critical_vulns += 1
                elif severity == 3:
                    sbom_high_vulns += 1
                elif severity == 2:
                    sbom_medium_vulns += 1
                elif severity == 1:
                    sbom_low_vulns += 1
            '''
            if package_vulns['max_severity'] == 4:
                sbom_critical_vulns += 1
            elif package_vulns['max_severity'] == 3:
                sbom_high_vulns += 1
            elif package_vulns['max_severity'] == 2:
                sbom_medium_vulns += 1
            elif package_vulns['max_severity'] == 1:
                sbom_low_vulns += 1
            '''

    if sbom.get('sbomqs_file'):
        sbomqs_file_path = os.path.join(sbom_folder, sbom["sbomqs_file"].split('/')[-1])
        sbom_quality = sbomqs_get_quality(sbomqs_file_path)

    if sbom.get('cyclonedx') is not None:
        sbom_cyclonedx_processed = True
        sbom_cyclonedx_res = sbom.get('cyclonedx')

    if sbom.get('sbom_utility') is not None:
        sbom_sbom_utility_processed = True
        sbom_sbom_utility_res = sbom.get('sbom_utility')

    if sbom.get('spdx_tool') is not None:
        sbom_pyspdxtools_processed = True
        sbom_pyspdxtools_res = sbom.get('pyspdxtools')

    if sbom.get('ntia_file'):
        sbom_ntia_processed = True
        with open(os.path.join(sbom_folder, sbom["ntia_file"]), 'r') as f:
            try:
                ntia_data = json.load(f)
                sbom_ntia_res = ntia_data.get('isNtiaConformant', False)
            except json.JSONDecodeError:
                sbom_ntia_res = False

    sbom_file_path = os.path.join(sbom_folder, sbom["file_name"])
    with open(sbom_file_path, 'r') as f:
        sbom_data = yaml.safe_load(f)

    sbom_successfully_processed = True

    relationships = sbom_data.get('relationships', [])
    # licensing_info = sbom_data.get('licensingInfo', [])

    sbom_version = sbom_data.get('spdxVersion', '')

    found_vulns = False
    dependencies = sbom_data.get('packages', [])
    sbom_dependencies_count = len(dependencies)
    if sbom_dependencies_count == 0:
        return [], []
    for dependency in dependencies:
        local_csv_dependency = []
        csv_licenses_list = []

        purl = ''
        ecosystem = ''
        spdxid = dependency.get('SPDXID', None)
        version = ''

        # get purl
        external_refs = dependency.get('externalRefs', [])
        for external_ref in external_refs:
            if external_ref.get('referenceType', '') == 'purl':
                purl = external_ref.get('referenceLocator', '')
                break

        if purl:
            purl = urllib.parse.unquote(purl)
            name = purl_get_name(purl)
            if name == '':
                name = dependency.get('name', '')
                name = urllib.parse.unquote(name)
            version = purl_get_version(purl)
            if version == '':
                version = dependency.get('versionInfo', '')
                version = urllib.parse.unquote(version)
            ecosystem = purl_get_ecosystem(purl)
        else:
            name = dependency.get('name', '')
            name = urllib.parse.unquote(name)
            version = dependency.get('version', '')
            version = urllib.parse.unquote(version)

        # add licenses
        license_declared = dependency.get('licenseDeclared', '')
        license_concluded = dependency.get('licenseConcluded', '')
        if license_declared == 'NOASSERTION':
            license_declared = ''
        if license_concluded == 'NOASSERTION':
            license_concluded = ''
        license_declared = spdx_retrieve_license_list(license_declared)
        license_concluded = spdx_retrieve_license_list(license_concluded)
        if license_declared:
            csv_licenses_list.extend(license_declared)
        elif license_concluded:
            csv_licenses_list.extend(license_concluded)
        csv_licenses_list = list(set(csv_licenses_list))
        sbom_licenses_count += len(csv_licenses_list)

        '''
        # get licenses from licensingInfo
        for license_index in range(len(csv_licenses_list)):
            license_enc = csv_licenses_list[license_index]
            for licensing_info_elem in licensing_info:
                if licensing_info_elem.get('licenseId', '') == license_enc:
                    csv_licenses_list[license_index] = licensing_info_elem.get('extractedText', '')
        '''

        cves = []
        cwes = []
        criticality = ''
        severity = []
        dependency_vulns = packages_with_vulns.get(f'{name}@{version}', {})
        if not dependency_vulns:
            dependency_vulns = packages_with_vulns.get(f'{name}@', {})
        if dependency_vulns:
            found_vulns = True
            cves = dependency_vulns.get('CVE', [])
            cwes = dependency_vulns.get('CWE', [])
            criticality = dependency_vulns.get('SEVERITY_SCORE', '')
            severity = dependency_vulns.get('SEVERITY', [])
            for severity_index in range(len(severity)):
                severity[severity_index] = SEVERITY_REVERSE_MAP.get(severity[severity_index], 'NONE')

        # do relationships
        dep_relationships = []
        dep_relationship_types = []
        for relationship in relationships:
            if relationship.get('spdxElementId', '') == spdxid:
                dep_relationships.append(relationship.get('relatedSpdxElement', ''))
                dep_relationship_types.append(relationship.get('relationshipType', ''))

        checksum_list = dependency.get('checksums', [])
        checksum = ''
        checksum_algo = ''
        # get the first one
        for checksum in checksum_list:
            checksum_algo = checksum.get('algorithm', '')
            checksum = checksum.get('checksumValue', '')
            break

        local_csv_dependency.append(sbom_code)
        local_csv_dependency.append(name)
        local_csv_dependency.append(version)
        local_csv_dependency.append(purl)
        local_csv_dependency.append('|'.join(csv_licenses_list))
        local_csv_dependency.append('|'.join(cves))
        local_csv_dependency.append('|'.join(cwes))
        local_csv_dependency.append(criticality)
        local_csv_dependency.append('|'.join(severity))
        local_csv_dependency.append('|'.join(dep_relationships))
        local_csv_dependency.append('|'.join(dep_relationship_types))
        local_csv_dependency.append(checksum)
        local_csv_dependency.append(checksum_algo)
        local_csv_dependency.append(ecosystem)
        csv_dependency.append(local_csv_dependency)

    if not found_vulns and len(packages_with_vulns) > 0:
        print(f'No vulnerabilities found for {sbom_code}')

    csv_sbom.append(sbom_code)
    csv_sbom.append(repo_name)
    csv_sbom.append(sbom_url)
    csv_sbom.append(sbom_path)
    csv_sbom.append(sbom_dependencies_count)
    csv_sbom.append(sbom_licenses_count)
    csv_sbom.append(sbom_critical_vulns)
    csv_sbom.append(sbom_high_vulns)
    csv_sbom.append(sbom_medium_vulns)
    csv_sbom.append(sbom_low_vulns)
    csv_sbom.append(sbom_quality)
    csv_sbom.append(sbom_format)
    csv_sbom.append(sbom_version)
    csv_sbom.append(sbom_successfully_processed)
    csv_sbom.append(sbom_sbomqs_processed)
    csv_sbom.append(sbom_osv_processed)
    csv_sbom.append(sbom_cyclonedx_processed)
    csv_sbom.append(sbom_sbom_utility_processed)
    csv_sbom.append(sbom_pyspdxtools_processed)
    csv_sbom.append(sbom_ntia_processed)
    csv_sbom.append(sbom_cyclonedx_res)
    csv_sbom.append(sbom_sbom_utility_res)
    csv_sbom.append(sbom_pyspdxtools_res)
    csv_sbom.append(sbom_ntia_res)

    return csv_sbom, csv_dependency


async def get_csv_from_spdx_spdx(sbom, repo_name):
    sbom_code = sbom["file_name"]

    csv_sbom = []
    csv_dependency = []

    sbom_url = sbom["url"]
    sbom_path = sbom["path"]

    # get from dependencies
    sbom_dependencies_count = 0
    sbom_licenses_count = 0

    # get from osv file
    sbom_critical_vulns = 0
    sbom_high_vulns = 0
    sbom_medium_vulns = 0
    sbom_low_vulns = 0

    # get from sbomqs file
    sbom_quality = 0

    sbom_format = 'spdx_spdx'
    sbom_version = ''

    sbom_successfully_processed = False
    sbom_sbomqs_processed = False
    sbom_osv_processed = False
    sbom_cyclonedx_processed = False
    sbom_sbom_utility_processed = False
    sbom_pyspdxtools_processed = False
    sbom_ntia_processed = False

    sbom_cyclonedx_res = False
    sbom_sbom_utility_res = False
    sbom_pyspdxtools_res = False
    sbom_ntia_res = False

    packages_with_vulns = {}
    if sbom.get('osv_file'):
        sbom_osv_processed = True
        osv_file_path = os.path.join(sbom_folder, sbom["osv_file"].split('/')[-1])
        packages_with_vulns = osv_get_vulnerabilities(osv_file_path)
        for package in packages_with_vulns:
            package_vulns = packages_with_vulns[package]
            for severity in package_vulns['SEVERITY']:
                if severity == 4:
                    sbom_critical_vulns += 1
                elif severity == 3:
                    sbom_high_vulns += 1
                elif severity == 2:
                    sbom_medium_vulns += 1
                elif severity == 1:
                    sbom_low_vulns += 1
            '''
            if package_vulns['max_severity'] == 4:
                sbom_critical_vulns += 1
            elif package_vulns['max_severity'] == 3:
                sbom_high_vulns += 1
            elif package_vulns['max_severity'] == 2:
                sbom_medium_vulns += 1
            elif package_vulns['max_severity'] == 1:
                sbom_low_vulns += 1
            '''

    if sbom.get('sbomqs_file'):
        sbomqs_file_path = os.path.join(sbom_folder, sbom["sbomqs_file"].split('/')[-1])
        sbom_quality = sbomqs_get_quality(sbomqs_file_path)

    if sbom.get('cyclonedx') is not None:
        sbom_cyclonedx_processed = True
        sbom_cyclonedx_res = sbom.get('cyclonedx')

    if sbom.get('sbom_utility') is not None:
        sbom_sbom_utility_processed = True
        sbom_sbom_utility_res = sbom.get('sbom_utility')

    if sbom.get('spdx_tool') is not None:
        sbom_pyspdxtools_processed = True
        sbom_pyspdxtools_res = sbom.get('pyspdxtools')

    if sbom.get('ntia_file'):
        sbom_ntia_processed = True
        with open(os.path.join(sbom_folder, sbom["ntia_file"]), 'r') as f:
            try:
                ntia_data = json.load(f)
                sbom_ntia_res = ntia_data.get('isNtiaConformant', False)
            except json.JSONDecodeError:
                sbom_ntia_res = False

    sbom_file_path = os.path.join(sbom_folder, sbom["file_name"])
    parser = Parser()
    with open(sbom_file_path, 'r') as f:
        data = f.read()
    try:
        sbom_data: Document = parser.parse(data)
    except SPDXParsingError as e:
        csv_sbom.append(sbom_code)
        csv_sbom.append(repo_name)
        csv_sbom.append(sbom_url)
        csv_sbom.append(sbom_path)
        csv_sbom.append(sbom_dependencies_count)
        csv_sbom.append(sbom_licenses_count)
        csv_sbom.append(sbom_critical_vulns)
        csv_sbom.append(sbom_high_vulns)
        csv_sbom.append(sbom_medium_vulns)
        csv_sbom.append(sbom_low_vulns)
        csv_sbom.append(sbom_quality)
        csv_sbom.append(sbom_format)
        csv_sbom.append(sbom_version)
        csv_sbom.append(sbom_successfully_processed)
        csv_sbom.append(sbom_sbomqs_processed)
        csv_sbom.append(sbom_osv_processed)
        csv_sbom.append(sbom_cyclonedx_processed)
        csv_sbom.append(sbom_sbom_utility_processed)
        csv_sbom.append(sbom_pyspdxtools_processed)
        csv_sbom.append(sbom_ntia_processed)
        csv_sbom.append(sbom_cyclonedx_res)
        csv_sbom.append(sbom_sbom_utility_res)
        csv_sbom.append(sbom_pyspdxtools_res)
        csv_sbom.append(sbom_ntia_res)
        return csv_sbom, []
    except ExpressionParseError as e:
        csv_sbom.append(sbom_code)
        csv_sbom.append(repo_name)
        csv_sbom.append(sbom_url)
        csv_sbom.append(sbom_path)
        csv_sbom.append(sbom_dependencies_count)
        csv_sbom.append(sbom_licenses_count)
        csv_sbom.append(sbom_critical_vulns)
        csv_sbom.append(sbom_high_vulns)
        csv_sbom.append(sbom_medium_vulns)
        csv_sbom.append(sbom_low_vulns)
        csv_sbom.append(sbom_quality)
        csv_sbom.append(sbom_format)
        csv_sbom.append(sbom_version)
        csv_sbom.append(sbom_successfully_processed)
        csv_sbom.append(sbom_sbomqs_processed)
        csv_sbom.append(sbom_osv_processed)
        csv_sbom.append(sbom_cyclonedx_processed)
        csv_sbom.append(sbom_sbom_utility_processed)
        csv_sbom.append(sbom_pyspdxtools_processed)
        csv_sbom.append(sbom_ntia_processed)
        csv_sbom.append(sbom_cyclonedx_res)
        csv_sbom.append(sbom_sbom_utility_res)
        csv_sbom.append(sbom_pyspdxtools_res)
        csv_sbom.append(sbom_ntia_res)
        return csv_sbom, []
    except IndexError as e:
        csv_sbom.append(sbom_code)
        csv_sbom.append(repo_name)
        csv_sbom.append(sbom_url)
        csv_sbom.append(sbom_path)
        csv_sbom.append(sbom_dependencies_count)
        csv_sbom.append(sbom_licenses_count)
        csv_sbom.append(sbom_critical_vulns)
        csv_sbom.append(sbom_high_vulns)
        csv_sbom.append(sbom_medium_vulns)
        csv_sbom.append(sbom_low_vulns)
        csv_sbom.append(sbom_quality)
        csv_sbom.append(sbom_format)
        csv_sbom.append(sbom_version)
        csv_sbom.append(sbom_successfully_processed)
        csv_sbom.append(sbom_sbomqs_processed)
        csv_sbom.append(sbom_osv_processed)
        csv_sbom.append(sbom_cyclonedx_processed)
        csv_sbom.append(sbom_sbom_utility_processed)
        csv_sbom.append(sbom_pyspdxtools_processed)
        csv_sbom.append(sbom_ntia_processed)
        csv_sbom.append(sbom_cyclonedx_res)
        csv_sbom.append(sbom_sbom_utility_res)
        csv_sbom.append(sbom_pyspdxtools_res)
        csv_sbom.append(sbom_ntia_res)
        return csv_sbom, []
    except Exception as e:
        print(f'Error parsing SPDX file {sbom_code}: {e}')
        csv_sbom.append(sbom_code)
        csv_sbom.append(repo_name)
        csv_sbom.append(sbom_url)
        csv_sbom.append(sbom_path)
        csv_sbom.append(sbom_dependencies_count)
        csv_sbom.append(sbom_licenses_count)
        csv_sbom.append(sbom_critical_vulns)
        csv_sbom.append(sbom_high_vulns)
        csv_sbom.append(sbom_medium_vulns)
        csv_sbom.append(sbom_low_vulns)
        csv_sbom.append(sbom_quality)
        csv_sbom.append(sbom_format)
        csv_sbom.append(sbom_version)
        csv_sbom.append(sbom_successfully_processed)
        csv_sbom.append(sbom_sbomqs_processed)
        csv_sbom.append(sbom_osv_processed)
        csv_sbom.append(sbom_cyclonedx_processed)
        csv_sbom.append(sbom_sbom_utility_processed)
        csv_sbom.append(sbom_pyspdxtools_processed)
        csv_sbom.append(sbom_ntia_processed)
        csv_sbom.append(sbom_cyclonedx_res)
        csv_sbom.append(sbom_sbom_utility_res)
        csv_sbom.append(sbom_pyspdxtools_res)
        csv_sbom.append(sbom_ntia_res)
        return csv_sbom, []

    sbom_successfully_processed = True

    relationships = sbom_data.relationships
    # licensing_info = sbom_data.get('licensingInfo', [])

    if sbom_data.creation_info:
        sbom_version = sbom_data.creation_info.spdx_version

    found_vulns = False
    dependencies = sbom_data.packages
    sbom_dependencies_count = len(dependencies)
    if sbom_dependencies_count == 0:
        return [], []
    for dependency in dependencies:
        local_csv_dependency = []
        csv_licenses_list = []

        purl = ''
        ecosystem = ''
        spdxid = dependency.spdx_id
        version = ''

        # get purl
        external_refs = dependency.external_references
        for external_ref in external_refs:
            if external_ref.reference_type == 'purl':
                purl = external_ref.locator
                break

        if purl:
            purl = urllib.parse.unquote(purl)
            name = purl_get_name(purl)
            if name == '' and dependency.name:
                name = dependency.name
                name = urllib.parse.unquote(name)
            version = purl_get_version(purl)
            if version == '' and dependency.version:
                version = dependency.version
                version = urllib.parse.unquote(version)
            ecosystem = purl_get_ecosystem(purl)
        else:
            if dependency.name:
                name = dependency.name
                name = urllib.parse.unquote(name)
            if dependency.version:
                version = dependency.version
                version = urllib.parse.unquote(version)

        # add licenses
        license_declared = dependency.license_declared
        license_concluded = dependency.license_concluded
        if isinstance(license_declared, LicenseExpression):
            csv_licenses_list.extend(list(license_declared.objects))
        if isinstance(license_concluded, LicenseExpression):
            csv_licenses_list.extend(list(license_concluded.objects))
        csv_licenses_list = list(set(csv_licenses_list))
        sbom_licenses_count += len(csv_licenses_list)

        '''
        # get licenses from licensingInfo
        for license_index in range(len(csv_licenses_list)):
            license_enc = csv_licenses_list[license_index]
            for licensing_info_elem in licensing_info:
                if licensing_info_elem.get('licenseId', '') == license_enc:
                    csv_licenses_list[license_index] = licensing_info_elem.get('extractedText', '')
        '''

        cves = []
        cwes = []
        criticality = ''
        severity = []
        dependency_vulns = packages_with_vulns.get(f'{name}@{version}', {})
        if not dependency_vulns:
            dependency_vulns = packages_with_vulns.get(f'{name}@', {})
        if dependency_vulns:
            found_vulns = True
            cves = dependency_vulns.get('CVE', [])
            cwes = dependency_vulns.get('CWE', [])
            criticality = dependency_vulns.get('SEVERITY_SCORE', '')
            severity = dependency_vulns.get('SEVERITY', [])
            for severity_index in range(len(severity)):
                severity[severity_index] = SEVERITY_REVERSE_MAP.get(severity[severity_index], 'NONE')

        # do relationships
        dep_relationships = []
        dep_relationship_types = []
        for relationship in relationships:
            if relationship.spdx_element_id == spdxid:
                dep_relationships.append(relationship.related_spdx_element_id)
                dep_relationship_types.append(relationship.relationship_type.name)

        checksum_list = dependency.checksums
        checksum = ''
        checksum_algo = ''
        # get the first one
        for checksum in checksum_list:
            checksum_algo = checksum.algorithm.name
            checksum = checksum.value
            break

        local_csv_dependency.append(sbom_code)
        local_csv_dependency.append(name)
        local_csv_dependency.append(version)
        local_csv_dependency.append(purl)
        local_csv_dependency.append('|'.join(csv_licenses_list))
        local_csv_dependency.append('|'.join(cves))
        local_csv_dependency.append('|'.join(cwes))
        local_csv_dependency.append(criticality)
        local_csv_dependency.append('|'.join(severity))
        local_csv_dependency.append('|'.join(dep_relationships))
        local_csv_dependency.append('|'.join(dep_relationship_types))
        local_csv_dependency.append(checksum)
        local_csv_dependency.append(checksum_algo)
        local_csv_dependency.append(ecosystem)
        csv_dependency.append(local_csv_dependency)

    if not found_vulns and len(packages_with_vulns) > 0:
        print(f'No vulnerabilities found for {sbom_code}')

    csv_sbom.append(sbom_code)
    csv_sbom.append(repo_name)
    csv_sbom.append(sbom_url)
    csv_sbom.append(sbom_path)
    csv_sbom.append(sbom_dependencies_count)
    csv_sbom.append(sbom_licenses_count)
    csv_sbom.append(sbom_critical_vulns)
    csv_sbom.append(sbom_high_vulns)
    csv_sbom.append(sbom_medium_vulns)
    csv_sbom.append(sbom_low_vulns)
    csv_sbom.append(sbom_quality)
    csv_sbom.append(sbom_format)
    csv_sbom.append(sbom_version)
    csv_sbom.append(sbom_successfully_processed)
    csv_sbom.append(sbom_sbomqs_processed)
    csv_sbom.append(sbom_osv_processed)
    csv_sbom.append(sbom_cyclonedx_processed)
    csv_sbom.append(sbom_sbom_utility_processed)
    csv_sbom.append(sbom_pyspdxtools_processed)
    csv_sbom.append(sbom_ntia_processed)
    csv_sbom.append(sbom_cyclonedx_res)
    csv_sbom.append(sbom_sbom_utility_res)
    csv_sbom.append(sbom_pyspdxtools_res)
    csv_sbom.append(sbom_ntia_res)

    return csv_sbom, csv_dependency


async def get_csv_from_spdx_generic(sbom, repo_name):
    # open the file and read first 5 bytes
    sbom_file_path = os.path.join(sbom_folder, sbom["file_name"])
    with open(sbom_file_path, 'rb') as f:
        magic = f.read(3)
    if magic[0] == b'{':
        return await get_csv_from_spdx_json(sbom, repo_name)
    if magic == b'---':
        return await get_csv_from_spdx_yaml(sbom, repo_name)
    else:
        return await get_csv_from_spdx_spdx(sbom, repo_name)


async def main(folder=''):
    global data_folder, sbom_folder
    if folder == '':
        data_folder = os.path.abspath(os.getcwd())
        data_folder = utils.get_latest_data_folder(data_folder)
    else:
        data_folder = folder
    sbom_folder = os.path.join(data_folder, sbom_folder)

    with open(os.path.join(data_folder, 'assessed_sbom_list.json'), 'r') as f:
        sboms_by_author = json.load(f)

    popular_languages = list(set(utils.TOP_20_LANGUAGES) | set(utils.GITHUB_POPULAR_LANGUAGES))
    popular_repos_folder = os.path.join(data_folder, 'popular_repos')
    # for every language load corresponding repos
    repo_per_language = {}
    for language in popular_languages:
        repos_file = os.path.join(popular_repos_folder, f"top_repos_{language}")
        with open(repos_file, 'r') as f:
            repos = json.load(f)
        # sort tuple by second element from biggest to smallest
        repos.sort(key=lambda x: x[1], reverse=True)
        # get the set with only the first element of the tuple
        repos_set = set([repo[0] for repo in repos])
        # remove the "https://" from the beginning of the repo name
        repos_set = set([repo[8:] if repo.startswith("https://") else repo for repo in repos_set])
        repo_per_language[language] = repos_set

    sbom_per_language = {}
    for language in popular_languages:
        sbom_per_language[language] = 0
    sbom_per_language['other'] = 0

    csv_sbom_list = []
    csv_dependency_list = []
    counted_repo = 0
    for author in sboms_by_author:
        for repo in sboms_by_author[author]:
            for sbom in sboms_by_author[author][repo]:
                local_csv_sbom = []
                local_csv_dependency = []
                if sbom["type"] == "cyclonedx_json":
                    local_csv_sbom, local_csv_dependency = await get_csv_from_cyclonedx_json(sbom, repo)
                if sbom["type"] == "cyclonedx_xml":
                    local_csv_sbom, local_csv_dependency = await get_csv_from_cyclonedx_xml(sbom, repo)
                if sbom["type"] == "spdx_json":
                    local_csv_sbom, local_csv_dependency = await get_csv_from_spdx_json(sbom, repo)
                if sbom["type"] == "spdx_yaml":
                    local_csv_sbom, local_csv_dependency = await get_csv_from_spdx_yaml(sbom, repo)
                if sbom["type"] == "spdx_rdx" or sbom["type"] == "spdx_rdf":
                    local_csv_sbom, local_csv_dependency = await get_csv_from_spdx_rdf(sbom, repo)
                if sbom["type"] == "spdx_spdx":
                    local_csv_sbom, local_csv_dependency = await get_csv_from_spdx_spdx(sbom, repo)
                if sbom["type"] == "spdx_generic":
                    local_csv_sbom, local_csv_dependency = await get_csv_from_spdx_generic(sbom, repo)
                # remove sbom files with 0 dependencies
                if local_csv_sbom and local_csv_sbom[4] != 0:
                    github_url = f"github.com/{author}/{repo}"
                    # get the language of the repo
                    detected = False
                    sbom_repo_language = ''
                    for language in popular_languages:
                        if github_url in repo_per_language[language]:
                            sbom_per_language[language] += 1
                            sbom_repo_language = language
                            detected = True
                            break
                    if not detected:
                        sbom_repo_language = 'other'
                        sbom_per_language['other'] += 1
                    local_csv_sbom.append(sbom_repo_language)
                    csv_sbom_list.append(local_csv_sbom)
                    csv_dependency_list.extend(local_csv_dependency)
            counted_repo += 1
            if counted_repo % 100 == 0:
                print(f'Processed {counted_repo} repositories')

    # write to csv
    with open(os.path.join(data_folder, 'sbom_list.csv'), 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(csv_sbom_header)
        for csv_sbom_line in csv_sbom_list:
            writer.writerow(csv_sbom_line)

    with open(os.path.join(data_folder, 'dependency_list.csv'), 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(csv_dependency_header)
        for csv_dependency_line in csv_dependency_list:
            writer.writerow(csv_dependency_line)

    print('Number of SBOMs per language:')
    for language in popular_languages:
        print(f'{language}: {sbom_per_language[language]}')
    print(f'Other: {sbom_per_language["other"]}')

if __name__ == "__main__":
    asyncio.run(main())
