# ignoring files that starts with "score." or "osv." and ends with ".tar" or ".DS_Store"
import csv
import datetime
import json
import os
import sys
import xml.etree.ElementTree as ET
from typing import cast

from cyclonedx.model.bom import Bom
from spdx_tools.spdx.parser.parse_anything import parse_file

sbom_id_counter = 0


def get_files_list(root_dir: str) -> list[str]:
    all_files = []
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".DS_Store"):
                continue
            elif file.endswith(".tar"):
                continue
            elif file.startswith("score."):
                continue
            elif file.startswith("osv."):
                continue
            all_files.append(os.path.join(root, file))
    return all_files


class DependencyPerSbom:
    sbom_id: int = 0
    str_id: str = ""
    dependency_name: str = ""
    dependency_version: str = ""
    dependency_location: str = ""
    dependency_license_list: list[str] = []
    dependency_cve: list[str] = []
    dependency_cve_criticality: list[str] = []
    dependency_cvss: list[str] = []
    dependency_cwe: list[str] = []
    dependency_reference: list[str] = []
    dependency_reference_type: list[str] = []
    dependency_relationship_list: list[str] = []
    dependency_relationship_type: list[str] = []
    dependency_checksum: str = ""
    dependency_checksum_algorithm: str = ""

    def __init__(self):
        self.sbom_id = 0
        self.str_id = ""
        self.dependency_name = ""
        self.dependency_version = ""
        self.dependency_location = ""
        self.dependency_license_list = []
        self.dependency_cve = []
        self.dependency_cve_criticality = []
        self.dependency_cvss = []
        self.dependency_cwe = []
        self.dependency_checksum = ""
        self.dependency_checksum_algorithm = ""
        self.dependency_relationship_list = []
        self.dependency_relationship_type = []
        self.dependency_reference = []
        self.dependency_reference_type = []


class SBOMData:
    id: int = 0
    project_name: str = ""
    project_url: str = ""
    dependency_count: int = 0
    licenses_count: int = 0
    licenses_set: set[str] = set()
    critical_cves_count: int = 0
    high_cves_count: int = 0
    medium_cves_count: int = 0
    low_cves_count: int = 0
    sbomqs_rating: float = 0.0
    format: str = ""
    format_version: str = ""
    creation_time: str = ""
    origin: str = ""
    tool: str = ""

    def __init__(self):
        global sbom_id_counter
        self.id = sbom_id_counter
        sbom_id_counter += 1
        self.project_name = ""
        self.project_url = ""
        self.format = ""
        self.format_version = ""
        self.creation_time = ""
        self.origin = ""
        self.dependency_count = 0
        self.sbomqs_rating = 0.0
        self.licenses_count = 0
        self.licenses_set = set()
        self.critical_cves_count = 0
        self.high_cves_count = 0
        self.medium_cves_count = 0
        self.low_cves_count = 0


def add_osv_data_to_dependency_per_sbom(dependency_per_sbom: DependencyPerSbom, osv_data_json: dict):
    if osv_data_json and osv_data_json["results"]:
        for package in osv_data_json["results"][0]["packages"]:
            if package["package"]["name"] == dependency_per_sbom.dependency_name:
                for vulnerability in package["vulnerabilities"]:
                    if not vulnerability.get("severity"):
                        continue
                    if vulnerability.get("aliases"):
                        dependency_per_sbom.dependency_cve.append(vulnerability["aliases"][0])
                    else:
                        dependency_per_sbom.dependency_cve.append(vulnerability["id"])
                    if isinstance(vulnerability["severity"], str):
                        dependency_per_sbom.dependency_cve_criticality.append(vulnerability["severity"])
                    else:
                        cvss_score = vulnerability["severity"][0]["score"]
                        severity_score = float(cvss_score[cvss_score.find(":") + 1: cvss_score.find("/")])
                        if severity_score >= 9.0:
                            dependency_per_sbom.dependency_cve_criticality.append("CRITICAL")
                        elif severity_score >= 7.0:
                            dependency_per_sbom.dependency_cve_criticality.append("HIGH")
                        elif severity_score >= 4.0:
                            dependency_per_sbom.dependency_cve_criticality.append("MEDIUM")
                        elif severity_score >= 0.1:
                            dependency_per_sbom.dependency_cve_criticality.append("LOW")
                        dependency_per_sbom.dependency_cvss.append(cvss_score)
                    if vulnerability.get("database_specific") and vulnerability["database_specific"].get("cwe_ids"):
                        for cwe in vulnerability["database_specific"]["cwe_ids"]:
                            dependency_per_sbom.dependency_cwe.append(cwe)
    if not osv_data_json:
        dependency_per_sbom.dependency_cve = None
        dependency_per_sbom.dependency_cve_criticality = None
        dependency_per_sbom.dependency_cvss = None
        dependency_per_sbom.dependency_cwe = None


def add_osv_data_to_sbomdata(sbomdata: SBOMData, osv_data_json: dict):
    # check if osv file is not empty
    if osv_data_json and osv_data_json["results"]:
        for package in osv_data_json["results"][0]["packages"]:
            for vulnerability in package["vulnerabilities"]:
                if not vulnerability.get("severity"):
                    continue
                if isinstance(vulnerability["severity"], str):
                    severity = vulnerability["severity"]
                    if severity == "CRITICAL":
                        sbomdata.critical_cves_count += 1
                    elif severity == "HIGH":
                        sbomdata.high_cves_count += 1
                    elif severity == "MEDIUM" or severity == "MODERATE":
                        sbomdata.medium_cves_count += 1
                    elif severity == "LOW":
                        sbomdata.low_cves_count += 1
                else:
                    cvss_score = vulnerability["severity"][0]["score"]
                    severity_score = float(cvss_score[cvss_score.find(":") + 1: cvss_score.find("/")])
                    if severity_score >= 9.0:
                        sbomdata.critical_cves_count += 1
                    elif severity_score >= 7.0:
                        sbomdata.high_cves_count += 1
                    elif severity_score >= 4.0:
                        sbomdata.medium_cves_count += 1
                    elif severity_score >= 0.1:
                        sbomdata.low_cves_count += 1
    elif not osv_data_json:
        sbomdata.critical_cves_count = -1
        sbomdata.high_cves_count = -1
        sbomdata.medium_cves_count = -1
        sbomdata.low_cves_count = -1


def get_docker_sbom_data(docker_sbom_filepath_list: list[str]) -> tuple[list[SBOMData], list[DependencyPerSbom]]:
    return get_spdx_json_sbom_data(docker_sbom_filepath_list, "docker")


def get_git_sbom_data(git_sbom_filepath_list: list[str]) -> tuple[list[SBOMData], list[DependencyPerSbom]]:
    github_sbom_filepath_list = []
    for sbom_filepath in git_sbom_filepath_list:
        # if filename not equals to "github.sbom.spdx.json" skip it
        if sbom_filepath.endswith("github.sbom.spdx.json"):
            github_sbom_filepath_list.append(sbom_filepath)
    return get_spdx_json_sbom_data(github_sbom_filepath_list, "github")


def get_spdx_json_sbom_data(git_sbom_filepath_list: list[str], origin: str = "sourcegraph") -> (tuple)[list[SBOMData], list[DependencyPerSbom]]:
    global sbom_id_counter
    sbomdata_list: list[SBOMData] = []
    dependency_per_sbom_list: list[DependencyPerSbom] = []

    for sbom_filepath in git_sbom_filepath_list:
        # read sbom file
        with open(sbom_filepath, 'r') as sbom_file:
            try:
                sbom_data_json = json.load(sbom_file)
            except json.decoder.JSONDecodeError:
                continue
            if sbom_data_json.get("sbom"):
                sbom_data_json = sbom_data_json["sbom"]
        new_sbomdata = SBOMData()
        sbomdata_list.append(new_sbomdata)
        try:
            new_sbomdata.project_name = sbom_data_json["name"]
        except KeyError:
            sbomdata_list.pop()
            sbom_id_counter -= 1
            continue
        new_sbomdata.project_url = (sbom_data_json["documentNamespace"])[
                                   :sbom_data_json["documentNamespace"].rfind("/")]
        new_sbomdata.format = "spdx"
        new_sbomdata.format_version = sbom_data_json["spdxVersion"]
        new_sbomdata.creation_time = sbom_data_json["creationInfo"]["created"]
        new_sbomdata.origin = origin
        new_sbomdata.dependency_count = len(sbom_data_json.get("packages", []))
        for creator in sbom_data_json["creationInfo"]["creators"]:
            if creator.startswith("Tool:"):
                new_sbomdata.tool = creator[5:]
                new_sbomdata.tool = new_sbomdata.tool.strip()
                break

        folder_names = sbom_filepath.split("/")[-3:-1]
        if new_sbomdata.tool.startswith("bom"):
            # then name should be the same as the folder name
            if folder_names[0] == "docker_folder":
                new_sbomdata.project_name = folder_names[-1] + ":latest"
            else:
                new_sbomdata.project_name = "/".join(folder_names)
        if folder_names[0] == "docker_folder":
            new_sbomdata.project_url = f"https://hub.docker.com/_/{folder_names[-1]}"
        else:
            new_sbomdata.project_url = f"https://github.com/{folder_names[0]}/{folder_names[1]}"


        # read score file
        # add `score.` prefix to the filename and if file extension is not .json, append .json to the filename
        score_filepath = os.path.join(os.path.dirname(sbom_filepath), 'score.' + os.path.basename(sbom_filepath))
        if not score_filepath.endswith('.json'):
            score_filepath += '.json'
        with open(score_filepath, 'r') as score_file:
            score_data_json = json.load(score_file)
        # check if score file is not empty
        if score_data_json:
            new_sbomdata.sbomqs_rating = score_data_json["files"][0]["avg_score"]

        # read osv file
        # add `osv.` prefix to the filename and if file extension is not .json, append .json to the filename
        osv_filepath = os.path.join(os.path.dirname(sbom_filepath), 'osv.' + os.path.basename(sbom_filepath))
        if not osv_filepath.endswith('.json'):
            osv_filepath += '.json'
        with open(osv_filepath, 'r') as osv_file:
            osv_data_json = json.load(osv_file)
        add_osv_data_to_sbomdata(new_sbomdata, osv_data_json)

        for package in sbom_data_json.get("packages", []):
            new_dependency_per_sbom = DependencyPerSbom()
            dependency_per_sbom_list.append(new_dependency_per_sbom)
            new_dependency_per_sbom.sbom_id = new_sbomdata.id
            new_dependency_per_sbom.str_id = package["SPDXID"]
            new_dependency_per_sbom.dependency_name = package["name"]
            new_dependency_per_sbom.dependency_version = package.get("versionInfo")
            if not new_dependency_per_sbom.dependency_version:
                new_dependency_per_sbom.dependency_version = ""
            new_dependency_per_sbom.dependency_license_list = package.get("licenseDeclared", "").split(" AND ")
            for license in new_dependency_per_sbom.dependency_license_list:
                if license and license != "NOASSERTION" and license != "NONE":
                    new_sbomdata.licenses_set.add(license)
            if package.get("checksums"):
                package_checksum = package["checksums"][0]
                new_dependency_per_sbom.dependency_checksum = package_checksum["checksumValue"]
                new_dependency_per_sbom.dependency_checksum_algorithm = package_checksum["algorithm"]
            for relationship in sbom_data_json.get("relationships", []):
                if relationship["spdxElementId"] == new_dependency_per_sbom.str_id:
                    new_dependency_per_sbom.dependency_relationship_list.append(relationship["relatedSpdxElement"])
                    new_dependency_per_sbom.dependency_relationship_type.append(relationship["relationshipType"])
            if package.get("externalRefs"):
                external_references = package["externalRefs"]
                # sort external references by referenceType
                external_references.sort(key=lambda x: x["referenceType"])
                for reference in package.get("externalRefs"):
                    new_dependency_per_sbom.dependency_reference.append(reference["referenceLocator"])
                    new_dependency_per_sbom.dependency_reference_type.append(reference["referenceType"])
                for reference_index in range(len(new_dependency_per_sbom.dependency_reference)):
                    if new_dependency_per_sbom.dependency_reference_type[reference_index] == "PACKAGE-MANAGER":
                        # remove this index from dependency_reference and dependency_reference_type
                        first_elem = new_dependency_per_sbom.dependency_reference.pop(reference_index)
                        new_dependency_per_sbom.dependency_reference.insert(0, first_elem)
                        first_elem_type = new_dependency_per_sbom.dependency_reference_type.pop(reference_index)
                        new_dependency_per_sbom.dependency_reference_type.insert(0, first_elem_type)
                        new_dependency_per_sbom.dependency_location = first_elem
                        break
            add_osv_data_to_dependency_per_sbom(new_dependency_per_sbom, osv_data_json)
            for reference_index in range(len(new_dependency_per_sbom.dependency_reference)):
                if new_dependency_per_sbom.dependency_reference_type[reference_index] == "SECURITY":
                    if new_dependency_per_sbom.dependency_reference[reference_index].lower().find("cve-") != -1:
                        cve_str_index = new_dependency_per_sbom.dependency_reference[reference_index].lower().find("cve-")
                        if new_dependency_per_sbom.dependency_cve is None:
                            new_dependency_per_sbom.dependency_cve = []
                        if new_dependency_per_sbom.dependency_cve_criticality is None:
                            new_dependency_per_sbom.dependency_cve_criticality = []
                        if new_dependency_per_sbom.dependency_cvss is None:
                            new_dependency_per_sbom.dependency_cvss = []
                        new_dependency_per_sbom.dependency_cve.append(
                            new_dependency_per_sbom.dependency_reference[reference_index][cve_str_index:])
                        new_dependency_per_sbom.dependency_cve_criticality.append("")
                        new_dependency_per_sbom.dependency_cvss.append("")
    return sbomdata_list, dependency_per_sbom_list


def get_spdx_sbom_data(spdx_sbom_filepath_list: list[str], origin: str = "sourcegraph") -> (tuple)[list[SBOMData], list[DependencyPerSbom]]:
    sbomdata_list: list[SBOMData] = []
    dependency_per_sbom_list: list[DependencyPerSbom] = []

    for sbom_filepath in spdx_sbom_filepath_list:
        try:
            sbom_document = parse_file(sbom_filepath)
        except:
            continue
        new_sbomdata = SBOMData()
        sbomdata_list.append(new_sbomdata)
        new_sbomdata.project_name = sbom_document.creation_info.name
        new_sbomdata.project_url = (sbom_document.creation_info.document_namespace)[
                                   :sbom_document.creation_info.document_namespace.rfind("/")]
        new_sbomdata.format = "spdx"
        new_sbomdata.format_version = sbom_document.creation_info.spdx_version
        new_sbomdata.creation_time = str(sbom_document.creation_info.created)
        new_sbomdata.origin = origin
        new_sbomdata.dependency_count = len(sbom_document.packages)
        for creator in sbom_document.creation_info.creators:
            toolname = creator.name
            if toolname.startswith("Tool:"):
                new_sbomdata.tool = toolname[5:]
                new_sbomdata.tool = new_sbomdata.tool.strip()
                break

        folder_names = sbom_filepath.split("/")[-3:-1]
        if new_sbomdata.tool.startswith("bom"):
            # then name should be the same as the folder name
            if folder_names[0] == "docker_folder":
                new_sbomdata.project_name = folder_names[-1] + ":latest"
            else:
                new_sbomdata.project_name = "/".join(folder_names)
        if folder_names[0] == "docker_folder":
            new_sbomdata.project_url = f"https://hub.docker.com/_/{folder_names[-1]}"
        else:
            new_sbomdata.project_url = f"https://github.com/{folder_names[0]}/{folder_names[1]}"

        # read score file
        # add `score.` prefix to the filename and if file extension is not .json, append .json to the filename
        score_filepath = os.path.join(os.path.dirname(sbom_filepath), 'score.' + os.path.basename(sbom_filepath))
        if not score_filepath.endswith('.json'):
            score_filepath += '.json'
        with open(score_filepath, 'r') as score_file:
            score_data_json = json.load(score_file)
        # check if score file is not empty
        if score_data_json:
            new_sbomdata.sbomqs_rating = score_data_json["files"][0]["avg_score"]

        # read osv file
        # add `osv.` prefix to the filename and if file extension is not .json, append .json to the filename
        osv_filepath = os.path.join(os.path.dirname(sbom_filepath), 'osv.' + os.path.basename(sbom_filepath))
        if not osv_filepath.endswith('.json'):
            osv_filepath += '.json'
        with open(osv_filepath, 'r') as osv_file:
            osv_data_json = json.load(osv_file)
        add_osv_data_to_sbomdata(new_sbomdata, osv_data_json)

        for package in sbom_document.packages:
            new_dependency_per_sbom = DependencyPerSbom()
            dependency_per_sbom_list.append(new_dependency_per_sbom)
            new_dependency_per_sbom.sbom_id = new_sbomdata.id
            new_dependency_per_sbom.str_id = package.spdx_id
            new_dependency_per_sbom.dependency_name = package.name
            new_dependency_per_sbom.dependency_version = package.version
            if not new_dependency_per_sbom.dependency_version:
                new_dependency_per_sbom.dependency_version = ""
            new_dependency_per_sbom.dependency_license_list = str(package.license_declared).split(" AND ")
            for license in new_dependency_per_sbom.dependency_license_list:
                if license and license != "NOASSERTION" and license != "NONE":
                    new_sbomdata.licenses_set.add(license)
            if package.checksums:
                package_checksum = package.checksums[0]
                new_dependency_per_sbom.dependency_checksum = package_checksum.value
                new_dependency_per_sbom.dependency_checksum_algorithm = str(package_checksum.algorithm)[str(package_checksum.algorithm).find(".") + 1:]
            for relationship in sbom_document.relationships:
                new_dependency_per_sbom.dependency_relationship_list.append(relationship.related_spdx_element_id)
                new_dependency_per_sbom.dependency_relationship_type.append(str(relationship.relationship_type)[str(relationship.relationship_type).find(".") + 1:])
            if package.external_references:
                external_references = package.external_references
                # sort external references by referenceType
                external_references.sort(key=lambda x: x.reference_type)
                for reference in external_references:
                    new_dependency_per_sbom.dependency_reference.append(reference.locator)
                    new_dependency_per_sbom.dependency_reference_type.append(reference.reference_type)
                for reference_index in range(len(new_dependency_per_sbom.dependency_reference)):
                    if new_dependency_per_sbom.dependency_reference_type[reference_index] == "PACKAGE-MANAGER":
                        # remove this index from dependency_reference and dependency_reference_type
                        first_elem = new_dependency_per_sbom.dependency_reference.pop(reference_index)
                        new_dependency_per_sbom.dependency_reference.insert(0, first_elem)
                        first_elem_type = new_dependency_per_sbom.dependency_reference_type.pop(reference_index)
                        new_dependency_per_sbom.dependency_reference_type.insert(0, first_elem_type)
                        new_dependency_per_sbom.dependency_location = first_elem
                        break
            add_osv_data_to_dependency_per_sbom(new_dependency_per_sbom, osv_data_json)
            for reference_index in range(len(new_dependency_per_sbom.dependency_reference)):
                if new_dependency_per_sbom.dependency_reference_type[reference_index] == "SECURITY":
                    if new_dependency_per_sbom.dependency_reference[reference_index].lower().find("cve-") != -1:
                        cve_str_index = new_dependency_per_sbom.dependency_reference[reference_index].lower().find(
                            "cve-")
                        if new_dependency_per_sbom.dependency_cve is None:
                            new_dependency_per_sbom.dependency_cve = []
                        new_dependency_per_sbom.dependency_cve.append(
                            new_dependency_per_sbom.dependency_reference[reference_index][cve_str_index:])
    return sbomdata_list, dependency_per_sbom_list


def get_cyclonedx_json_sbom_data(cyclonedx_json_sbom_filepath_list: list[str], origin: str = "sourcegraph") -> (tuple)[list[SBOMData], list[DependencyPerSbom]]:
    sbomdata_list: list[SBOMData] = []
    dependency_per_sbom_list: list[DependencyPerSbom] = []

    for sbom_filepath in cyclonedx_json_sbom_filepath_list:
        # read sbom file
        with open(sbom_filepath, 'r') as sbom_file:
            try:
                sbom_data_json = json.load(sbom_file)
            except json.decoder.JSONDecodeError:
                continue

        if not sbom_data_json.get("bomFormat"):
            continue

        new_sbomdata = SBOMData()
        sbomdata_list.append(new_sbomdata)
        if sbom_data_json.get("metadata") and sbom_data_json["metadata"].get("component"):
            new_sbomdata.project_name = sbom_data_json["metadata"]["component"]["name"]
            if sbom_data_json["metadata"]["component"].get("externalReferences"):
                new_sbomdata.project_url = sbom_data_json["metadata"]["component"].get("externalReferences")[0]["url"]
            elif sbom_data_json["metadata"]["component"].get("purl"):
                new_sbomdata.project_url = sbom_data_json["metadata"]["component"]["purl"]
            else:
                # get filename from `sbom_filepath` and only 2 directories before it
                new_sbomdata.project_url = "/" + "/".join(sbom_filepath.split("/")[-3:])
            if sbom_data_json["metadata"].get("timestamp"):
                new_sbomdata.creation_time = sbom_data_json["metadata"]["timestamp"]
            else:
                new_sbomdata.creation_time = ""
        else:
            new_sbomdata.project_name = "/" + "/".join(sbom_filepath.split("/")[-3:])
            new_sbomdata.project_url = "/" + "/".join(sbom_filepath.split("/")[-3:])
            new_sbomdata.creation_time = ""

        new_sbomdata.format = sbom_data_json["bomFormat"]
        new_sbomdata.format_version = sbom_data_json["specVersion"]
        new_sbomdata.origin = origin
        new_sbomdata.dependency_count = len(sbom_data_json.get("components", []))
        if sbom_data_json.get("metadata") and sbom_data_json["metadata"].get("tools"):
            if isinstance(sbom_data_json["metadata"]["tools"], list):
                for tool in sbom_data_json["metadata"]["tools"]:
                    new_sbomdata.tool = tool.get("name")
                    break
            elif isinstance(sbom_data_json["metadata"]["tools"], dict):
                if sbom_data_json["metadata"]["tools"].get("component") and sbom_data_json["metadata"]["tools"].get("component").get("name"):
                    new_sbomdata.tool = sbom_data_json["metadata"]["tools"].get("name")

        folder_names = sbom_filepath.split("/")[-3:-1]
        if folder_names[0] == "docker_folder":
            new_sbomdata.project_url = f"https://hub.docker.com/_/{folder_names[-1]}"
        else:
            new_sbomdata.project_url = f"https://github.com/{folder_names[0]}/{folder_names[1]}"

        # read score file
        # add `score.` prefix to the filename and if file extension is not .json, append .json to the filename
        score_filepath = os.path.join(os.path.dirname(sbom_filepath), 'score.' + os.path.basename(sbom_filepath))
        if not score_filepath.endswith('.json'):
            score_filepath += '.json'
        with open(score_filepath, 'r') as score_file:
            score_data_json = json.load(score_file)
        # check if score file is not empty
        if score_data_json:
            new_sbomdata.sbomqs_rating = score_data_json["files"][0]["avg_score"]

        # read osv file
        # add `osv.` prefix to the filename and if file extension is not .json, append .json to the filename
        osv_filepath = os.path.join(os.path.dirname(sbom_filepath), 'osv.' + os.path.basename(sbom_filepath))
        if not osv_filepath.endswith('.json'):
            osv_filepath += '.json'
        with open(osv_filepath, 'r') as osv_file:
            osv_data_json = json.load(osv_file)
        add_osv_data_to_sbomdata(new_sbomdata, osv_data_json)

        for component in sbom_data_json.get("components", []):
            new_dependency_per_sbom = DependencyPerSbom()
            dependency_per_sbom_list.append(new_dependency_per_sbom)
            new_dependency_per_sbom.sbom_id = new_sbomdata.id
            new_dependency_per_sbom.str_id = component.get("bom-ref")
            new_dependency_per_sbom.dependency_name = component["name"]
            new_dependency_per_sbom.dependency_version = component.get("version", "")
            if component.get("evidence") and component["evidence"].get("licenses"):
                for license in component["evidence"]["licenses"]:
                    if license.get("license"):
                        if license["license"].get("id"):
                            new_dependency_per_sbom.dependency_license_list.append(license["license"]["id"])
                            new_sbomdata.licenses_set.add(new_dependency_per_sbom.dependency_license_list[-1])
                        elif license["license"].get("name"):
                            new_dependency_per_sbom.dependency_license_list.append(license["license"]["name"])
                            new_sbomdata.licenses_set.add(new_dependency_per_sbom.dependency_license_list[-1])
            if component.get("licenses"):
                for license in component["licenses"]:
                    if license.get("license"):
                        if license["license"].get("id"):
                            new_dependency_per_sbom.dependency_license_list.append(license["license"]["id"])
                            new_sbomdata.licenses_set.add(new_dependency_per_sbom.dependency_license_list[-1])
                        elif license["license"].get("name"):
                            new_dependency_per_sbom.dependency_license_list.append(license["license"]["name"])
                            new_sbomdata.licenses_set.add(new_dependency_per_sbom.dependency_license_list[-1])
            else:
                new_dependency_per_sbom.dependency_license_list = []
            if component.get("hashes"):
                new_dependency_per_sbom.dependency_checksum = component["hashes"][0]["content"]
                new_dependency_per_sbom.dependency_checksum_algorithm = component["hashes"][0]["alg"]
            if component.get("purl"):
                new_dependency_per_sbom.dependency_location = component["purl"]
                new_dependency_per_sbom.dependency_reference.append(component["purl"])
                new_dependency_per_sbom.dependency_reference_type.append("")
            if component.get("externalReferences"):
                external_references = component["externalReferences"]
                # sort external references by referenceType
                external_references.sort(key=lambda x: x["type"])
                for reference in component.get("externalReferences"):
                    new_dependency_per_sbom.dependency_reference.append(reference["url"])
                    new_dependency_per_sbom.dependency_reference_type.append(reference["type"])
            for relationship in sbom_data_json.get("dependencies", []):
                if relationship["ref"] == new_dependency_per_sbom.str_id and relationship.get("dependsOn"):
                    new_dependency_per_sbom.dependency_relationship_list.extend(relationship["dependsOn"])
                    new_dependency_per_sbom.dependency_relationship_type.append("dependsOn")
            add_osv_data_to_dependency_per_sbom(new_dependency_per_sbom, osv_data_json)
    return sbomdata_list, dependency_per_sbom_list


def get_cyclonedx_xml_sbom_data(cyclonedx_xml_sbom_filepath_list: list[str], origin: str = "sourcegraph") -> (tuple)[list[SBOMData], list[DependencyPerSbom]]:
    sbomdata_list: list[SBOMData] = []
    dependency_per_sbom_list: list[DependencyPerSbom] = []

    for sbom_filepath in cyclonedx_xml_sbom_filepath_list:
        # read xml sbom file into a string
        with open(sbom_filepath, 'r') as sbom_file:
            sbom_filedata = sbom_file.read()
        try:
            tree = ET.fromstring(sbom_filedata)
            deserialized_bom = cast(Bom, Bom.from_xml(data=tree))
        except:
            continue
        # convert deserialized_bom to json
        new_sbomdata = SBOMData()
        sbomdata_list.append(new_sbomdata)
        if deserialized_bom.metadata and deserialized_bom.metadata.component:
            new_sbomdata.project_name = not deserialized_bom.metadata.component.name
            if deserialized_bom.metadata.component.external_references:
                new_sbomdata.project_url = (deserialized_bom.metadata.component.external_references[0]).url
            elif deserialized_bom.metadata.component.purl:
                new_sbomdata.project_url = deserialized_bom.metadata.component.purl
            else:
                # get filename from `sbom_filepath` and only 2 directories before it
                new_sbomdata.project_url = "/" + "/".join(sbom_filepath.split("/")[-3:])
            if (deserialized_bom.metadata.timestamp
                    and deserialized_bom.metadata.timestamp.replace(tzinfo=None) < datetime.datetime.now() - datetime.timedelta(minutes=5)):
                new_sbomdata.creation_time = deserialized_bom.metadata.timestamp
            else:
                new_sbomdata.creation_time = ""
        else:
            new_sbomdata.project_name = "/" + "/".join(sbom_filepath.split("/")[-3:])
            new_sbomdata.project_url = "/" + "/".join(sbom_filepath.split("/")[-3:])
            new_sbomdata.creation_time = ""

        new_sbomdata.format = "CycloneDX"
        new_sbomdata.format_version = ""
        new_sbomdata.origin = origin
        new_sbomdata.dependency_count = len(deserialized_bom.components)
        if deserialized_bom.metadata and deserialized_bom.metadata.tools:
            for tool in deserialized_bom.metadata.tools:
                new_sbomdata.tool = tool.name
                break

        folder_names = sbom_filepath.split("/")[-3:-1]
        if folder_names[0] == "docker_folder":
            new_sbomdata.project_url = f"https://hub.docker.com/_/{folder_names[-1]}"
        else:
            new_sbomdata.project_url = f"https://github.com/{folder_names[0]}/{folder_names[1]}"

        # read score file
        # add `score.` prefix to the filename and if file extension is not .json, append .json to the filename
        score_filepath = os.path.join(os.path.dirname(sbom_filepath), 'score.' + os.path.basename(sbom_filepath))
        if not score_filepath.endswith('.json'):
            score_filepath += '.json'
        with open(score_filepath, 'r') as score_file:
            score_data_json = json.load(score_file)
        # check if score file is not empty
        if score_data_json:
            new_sbomdata.sbomqs_rating = score_data_json["files"][0]["avg_score"]

        # read osv file
        # add `osv.` prefix to the filename and if file extension is not .json, append .json to the filename
        osv_filepath = os.path.join(os.path.dirname(sbom_filepath), 'osv.' + os.path.basename(sbom_filepath))
        if not osv_filepath.endswith('.json'):
            osv_filepath += '.json'
        with open(osv_filepath, 'r') as osv_file:
            osv_data_json = json.load(osv_file)
        # check if osv file is not empty
        if osv_data_json and osv_data_json["results"]:
            for package in osv_data_json["results"][0]["packages"]:
                for vulnerability in package["vulnerabilities"]:
                    if not vulnerability.get("severity"):
                        continue
                    cvss_score = vulnerability["severity"][0]["score"]
                    severity_score = float(cvss_score[cvss_score.find(":") + 1: cvss_score.find("/")])
                    if severity_score >= 9.0:
                        new_sbomdata.critical_cves_count += 1
                    elif severity_score >= 7.0:
                        new_sbomdata.high_cves_count += 1
                    elif severity_score >= 4.0:
                        new_sbomdata.medium_cves_count += 1
                    elif severity_score >= 0.1:
                        new_sbomdata.low_cves_count += 1
        else:
            new_sbomdata.critical_cves_count = -1
            new_sbomdata.high_cves_count = -1
            new_sbomdata.medium_cves_count = -1
            new_sbomdata.low_cves_count = -1

        for component in deserialized_bom.components:
            new_dependency_per_sbom = DependencyPerSbom()
            dependency_per_sbom_list.append(new_dependency_per_sbom)
            new_dependency_per_sbom.sbom_id = new_sbomdata.id
            new_dependency_per_sbom.str_id = component.bom_ref
            new_dependency_per_sbom.dependency_name = component.name
            new_dependency_per_sbom.dependency_version = component.version
            if new_dependency_per_sbom.dependency_name.startswith("${"):
                # remove this dependency from dependency_per_sbom_list
                dependency_per_sbom_list.pop()
                continue
            if component.evidence and component.evidence.licenses:
                if component.evidence.licenses[0]:
                    if (component.evidence.licenses[0]).id:
                        new_dependency_per_sbom.dependency_license = (component.evidence.licenses[0]).id
                        new_sbomdata.licenses_count += 1
                    elif (component.evidence.licenses[0]).name:
                        new_dependency_per_sbom.dependency_license = (component.evidence.licenses[0]).name
                        new_sbomdata.licenses_count += 1
            if component.licenses:
                for license in component.licenses:
                    try:
                        if license.id:
                            new_dependency_per_sbom.dependency_license_list.append(license.id)
                            new_sbomdata.licenses_set.add(license.id)
                    except AttributeError:
                        try:
                            if license.name:
                                new_dependency_per_sbom.dependency_license_list.append(license.name)
                                new_sbomdata.licenses_set.add(license.name)
                        except AttributeError:
                            continue
            else:
                new_dependency_per_sbom.dependency_license_list = []
            if component.hashes:
                hash = component.hashes[0]
                new_dependency_per_sbom.dependency_checksum = hash.content
                new_dependency_per_sbom.dependency_checksum_algorithm = str(hash.alg)[str(hash.alg).find(".") + 1:]
            if component.purl:
                new_dependency_per_sbom.dependency_reference.append(str(component.purl))
                new_dependency_per_sbom.dependency_location = str(component.purl)
                new_dependency_per_sbom.dependency_reference_type.append("")
            if component.external_references:
                external_references = component.external_references
                for reference in external_references:
                    new_dependency_per_sbom.dependency_reference.append(reference.url)
                    new_dependency_per_sbom.dependency_reference_type.append(reference.type)
            for relationship in deserialized_bom.dependencies:
                if relationship.ref == new_dependency_per_sbom.str_id and relationship.dependencies:
                    for dependency in relationship.dependencies:
                        new_dependency_per_sbom.dependency_relationship_list.append(dependency.ref.value)
                        new_dependency_per_sbom.dependency_relationship_type.append("dependsOn")
            add_osv_data_to_dependency_per_sbom(new_dependency_per_sbom, osv_data_json)
    return sbomdata_list, dependency_per_sbom_list


def dump_sbomdata_to_csv(sbomdata_list: list[SBOMData]):
    with open('sbomdata.csv', 'w', newline='') as csvfile:
        fieldnames = ['id', 'project_name', 'project_url', 'dependency_count', 'licenses_count', 'critical_cves_count',
                      'high_cves_count', 'medium_cves_count', 'low_cves_count', 'sbomqs_rating', 'format',
                      'format_version', 'creation_time', 'origin', 'tool']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for sbomdata in sbomdata_list:
            for license in sbomdata.licenses_set:
                if license:
                    sbomdata.licenses_count += 1
            writer.writerow({'id': sbomdata.id, 'project_name': sbomdata.project_name,
                             'project_url': sbomdata.project_url, 'dependency_count': sbomdata.dependency_count,
                             'licenses_count': sbomdata.licenses_count,
                             'critical_cves_count': sbomdata.critical_cves_count,
                             'high_cves_count': sbomdata.high_cves_count,
                             'medium_cves_count': sbomdata.medium_cves_count,
                             'low_cves_count': sbomdata.low_cves_count,
                             'sbomqs_rating': round(sbomdata.sbomqs_rating, 2),
                             'format': sbomdata.format, 'format_version': sbomdata.format_version,
                             'creation_time': sbomdata.creation_time, 'origin': sbomdata.origin,
                             'tool': sbomdata.tool})


def dump_dependency_per_sbom_to_csv(dependency_per_sbom_list: list[DependencyPerSbom]):
    fieldnames = ['sbom_id', 'dependency_name', 'dependency_license',
                      'dependency_cve', 'dependency_cwe', 'dependency_cve_criticality', 'dependency_cvss',
                      'dependency_relationship_list', 'dependency_relationship_type', 'dependency_checksum',
                      'dependency_checksum_algorithm', ]
    with open('dependency_per_sbom.csv', 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for dependency_per_sbom in dependency_per_sbom_list:
            if dependency_per_sbom.dependency_cve is None:
                cve_list = "NA"
            else:
                cve_list = "|".join(dependency_per_sbom.dependency_cve)
            if dependency_per_sbom.dependency_cwe is None:
                cwe_list = "NA"
            else:
                cwe_list = "|".join(dependency_per_sbom.dependency_cwe)
            if dependency_per_sbom.dependency_cve_criticality is None:
                cve_criticality_list = "NA"
            else:
                cve_criticality_list = "|".join(dependency_per_sbom.dependency_cve_criticality)
            if dependency_per_sbom.dependency_cvss is None:
                cvss_list = "NA"
            else:
                cvss_list = "|".join(dependency_per_sbom.dependency_cvss)
            writer.writerow({'sbom_id': dependency_per_sbom.sbom_id,
                             'dependency_name': dependency_per_sbom.dependency_name,
                             'dependency_license': "|".join(dependency_per_sbom.dependency_license_list),
                             'dependency_checksum': dependency_per_sbom.dependency_checksum,
                             'dependency_checksum_algorithm': dependency_per_sbom.dependency_checksum_algorithm,
                             'dependency_relationship_list': "|".join(dependency_per_sbom.dependency_relationship_list),
                             'dependency_relationship_type': "|".join(dependency_per_sbom.dependency_relationship_type),
                             'dependency_cve': cve_list,
                             'dependency_cve_criticality': cve_criticality_list,
                             'dependency_cvss': cvss_list,
                             'dependency_cwe': cwe_list})


def csv_splitter():
    csv.field_size_limit(sys.maxsize)
    fieldnames = ['sbom_id', 'dependency_name', 'dependency_license',
                  'dependency_cve', 'dependency_cwe', 'dependency_cve_criticality', 'dependency_cvss',
                  'dependency_relationship_list', 'dependency_relationship_type', 'dependency_checksum',
                  'dependency_checksum_algorithm', ]
    # split dependency_per_sbom.csv into multiple files
    with open('dependency_per_sbom.csv', 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        sbom_id_dependency_per_sbom_dict = {}
        for row in reader:
            if row["sbom_id"] in sbom_id_dependency_per_sbom_dict:
                sbom_id_dependency_per_sbom_dict[row["sbom_id"]].append(row)
            else:
                sbom_id_dependency_per_sbom_dict[row["sbom_id"]] = [row]
    for sbom_index in range(0, 260, 260//4):
        with open(f'dependency_per_sbom_docker{sbom_index}.csv', 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for sbom_id in range(sbom_index, sbom_index + 260//4):
                if str(sbom_id) in sbom_id_dependency_per_sbom_dict:
                    for row in sbom_id_dependency_per_sbom_dict[str(sbom_id)]:
                        writer.writerow(row)
    with open(f'dependency_per_sbom_other.csv', 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for sbom_index in range(260, len(sbom_id_dependency_per_sbom_dict)):
            if str(sbom_index) in sbom_id_dependency_per_sbom_dict:
                for row in sbom_id_dependency_per_sbom_dict[str(sbom_index)]:
                    writer.writerow(row)


def main():
    root_dir = os.path.abspath("sbom_storage_dir/")
    sbomdata_list: list[SBOMData] = []
    dependency_per_sbom_list: list[DependencyPerSbom] = []

    # get files from docker_folder folder
    # get docker_folder folder path
    docker_root_dir = os.path.join(root_dir, "docker_folder")
    docker_sbom_filepath_list = get_files_list(docker_root_dir)
    temp_sbomdata_list, temp_dependency_per_sbom_list = get_docker_sbom_data(docker_sbom_filepath_list)
    sbomdata_list.extend(temp_sbomdata_list)
    dependency_per_sbom_list.extend(temp_dependency_per_sbom_list)


    # get files from git folder
    # get git folder path
    git_root_dir = os.path.join(root_dir, "git_repos")
    git_sbom_filepath_list = get_files_list(git_root_dir)
    temp_sbomdata_list, temp_dependency_per_sbom_list = get_git_sbom_data(git_sbom_filepath_list)
    sbomdata_list.extend(temp_sbomdata_list)
    dependency_per_sbom_list.extend(temp_dependency_per_sbom_list)

    # get sourcegraph folder path
    sourcegraph_root_dir = os.path.join(root_dir, "sourcegraph")

    # get files from cyclonedx_json folder
    # get cyclonedx_json folder path
    cyclonedx_json_root_dir = os.path.join(sourcegraph_root_dir, "cyclonedx_json")
    cyclonedx_json_sbom_filepath_list = get_files_list(cyclonedx_json_root_dir)
    temp_sbomdata_list, temp_dependency_per_sbom_list = get_cyclonedx_json_sbom_data(cyclonedx_json_sbom_filepath_list)
    sbomdata_list.extend(temp_sbomdata_list)
    dependency_per_sbom_list.extend(temp_dependency_per_sbom_list)

    # get files from cyclonedx_xml folder
    # get cyclonedx_xml folder path
    cyclonedx_xml_root_dir = os.path.join(sourcegraph_root_dir, "cyclonedx_xml")
    cyclonedx_xml_sbom_filepath_list = get_files_list(cyclonedx_xml_root_dir)
    temp_sbomdata_list, temp_dependency_per_sbom_list = get_cyclonedx_xml_sbom_data(cyclonedx_xml_sbom_filepath_list)
    sbomdata_list.extend(temp_sbomdata_list)
    dependency_per_sbom_list.extend(temp_dependency_per_sbom_list)

    # get files from spdx_2_1_json folder
    # get spdx_2_1_json folder path
    spdx_2_1_json_root_dir = os.path.join(sourcegraph_root_dir, "spdx_2_1_json")
    spdx_2_1_json_sbom_filepath_list = get_files_list(spdx_2_1_json_root_dir)
    temp_sbomdata_list, temp_dependency_per_sbom_list = get_spdx_json_sbom_data(spdx_2_1_json_sbom_filepath_list)
    sbomdata_list.extend(temp_sbomdata_list)
    dependency_per_sbom_list.extend(temp_dependency_per_sbom_list)

    # get files from spdx_2_2_json folder
    # get spdx_2_2_json folder path
    spdx_2_2_json_root_dir = os.path.join(sourcegraph_root_dir, "spdx_2_2_json")
    spdx_2_2_json_sbom_filepath_list = get_files_list(spdx_2_2_json_root_dir)
    temp_sbomdata_list, temp_dependency_per_sbom_list = get_spdx_json_sbom_data(spdx_2_2_json_sbom_filepath_list)
    sbomdata_list.extend(temp_sbomdata_list)
    dependency_per_sbom_list.extend(temp_dependency_per_sbom_list)

    # get files from spdx_2_3_json folder
    # get spdx_2_3_json folder path
    spdx_2_3_json_root_dir = os.path.join(sourcegraph_root_dir, "spdx_2_3_json")
    spdx_2_3_json_sbom_filepath_list = get_files_list(spdx_2_3_json_root_dir)
    temp_sbomdata_list, temp_dependency_per_sbom_list = get_spdx_json_sbom_data(spdx_2_3_json_sbom_filepath_list)
    sbomdata_list.extend(temp_sbomdata_list)
    dependency_per_sbom_list.extend(temp_dependency_per_sbom_list)

    # get files from spdx_2_spdx folder
    # get spdx_2_spdx folder path
    spdx_2_spdx_root_dir = os.path.join(sourcegraph_root_dir, "spdx_2_spdx")
    spdx_2_spdx_sbom_filepath_list = get_files_list(spdx_2_spdx_root_dir)
    temp_sbomdata_list, temp_dependency_per_sbom_list = get_spdx_sbom_data(spdx_2_spdx_sbom_filepath_list)
    sbomdata_list.extend(temp_sbomdata_list)
    dependency_per_sbom_list.extend(temp_dependency_per_sbom_list)

    dump_sbomdata_to_csv(sbomdata_list)
    dump_dependency_per_sbom_to_csv(dependency_per_sbom_list)
    csv_splitter()

    return 0


if __name__ == "__main__":
    main()
