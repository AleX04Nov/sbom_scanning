# Steps to reproduce the dataset
## Step 1: Retrieve SBOM files
This following scripts retrieves SBOM files:
- Docker Hub. `1_docker_main.py` generates SBOM files with the help of `BOM`, `trivy`, `syft` and `docker scout cves`;
- GitHub. `1_github_main.py` retrieves information from the GitHub Insights API;
- Sourcegraph. `1_sourcegraph_main.py` retrieves the URL location of SBOM files in real-world projects. Utilizes several queries to get the: `cyclonedx(json)`, `cyclonedx(xml)`, `spdx_2.1(json)`, `spdx_2.2(json)`, `spdx_2.3(json)`, `spdx_2(spdx)`; 

## Step 2: Remove duplicates and empty files
The script `2_remove_duplicates.py` removes duplicate SBOM files and empty folders from the retrieved data. Duplication being searched by MD5 hash

## Step 3: Generate SBOM score files
The script `3_sbom_score_main.py` generates SBOM score files for each retrieved SBOM file. It utilizes `sbomqs` to generate SBOM scores.

## Step 4: Generate OSV files
The script `4_osv_scanner_main.py` generates OSV files for each retrieved SBOM file. It utilizes the `ghcr.io/google/osv-scanner` docker container to generate OSV files.

## Step 5: Generate final CVS dataset
The script `5_generate_final_dataset.py` generates the final CVS dataset from the SBOM, OSV, and score files.

The scripts need to run in the following order:
1. `1_docker_main.py`
2. `1_github_main.py`
3. `1_sourcegraph_main.py`
4. `2_remove_duplicates.py`
5. `3_sbom_score_main.py`
6. `4_osv_scanner_main.py`
7. `5_combination.py`

Steps 1-3 are optional, as the data is already provided in the `data` folder. Steps 4-6 are necessary to generate the final dataset. Step 7 is optional, as the final dataset is already provided in the `data` folder.

All programs should be run from the root folder of the project.

## Requirements
You need to install those tools before trying to reproduce:
- `docker` - run containers and retrieve SBOM files from Docker Scout;
- `bom` - generate SBOM files from Docker containers;
- `trivy` - generate SBOM files from Docker containers;
- `syft` - generate SBOM files from Docker containers;
- `sbomqs` - generate SBOM scores;
- `ghcr.io/google/osv-scanner` - docker container to generate OSV files;

All Python requirements are provided in the `requirements.txt` file.
