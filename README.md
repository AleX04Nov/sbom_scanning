# Step 1: Retrieve SBOM files
This program retrieves SBOM files from the next specified locations:
- Docker Hub. This program generates SBOM files with the help of `BOM`, `trivy`, `syft` and `docker scout cves`;
- GitHub. Retrieves information from the GitHub insights API;
- Sourcegraph. Retrieves the URL location of SBOM files in real-world projects. Utilizes several queries to get the: `cyclonedx(json)`, `cyclonedx(xml)`, `spdx_2.1(json)`, `spdx_2.2(json)`, `spdx_2.3(json)`, `spdx_2(spdx)`; 

Consists of the following files:
- `1_docker_main.py` - retrieves SBOM files from Docker Hub;
- `1_github_main.py` - retrieves SBOM files from GitHub;
- `1_sourcegraph_main.py` - retrieves SBOM files from Sourcegraph;

# Step 2: Remove duplicates and empty files
This program removes duplicate SBOM files and empty folders from the retrieved data. Duplication being searched by md5 hash

Consists of the following files:
- `2_remove_duplicates.py` - removes duplicate SBOM files and empty folders;

# Step 3: Generate SBOM score files
This program generates SBOM score files for each retrieved SBOM file. Program utilizes `sbomqs` to generate SBOM scores.

Consists of the following files:
- `3_sbom_score_main.py` - generates SBOM score files;

# Step 4: Generate OSV files
This program generates OSV files for each retrieved SBOM file. Program utilizes `ghcr.io/google/osv-scanner` docker container to generate OSV files.

Consists of the following files:
- `4_osv_scanner_main.py` - generates OSV files;

# Step 5: Generate final CVS dataset
This program generates final CVS dataset from the existent set of SBOM, OSV, and SCORE files.

Consists of the following files:
- `5_generate_final_dataset.py` - generates final CVS dataset;

# Running
All programs should be run in the following order:
1. `1_docker_main.py`
2. `1_github_main.py`
3. `1_sourcegraph_main.py`
4. `2_remove_duplicates.py`
5. `3_sbom_score_main.py`
6. `4_osv_scanner_main.py`
7. `5_combination.py`

Steps 1-3 are optional, as the data is already provided in the `data` folder. Steps 4-6 are mandatory, as they generate the final dataset. Step 7 is optional, as the final dataset is already provided in the `data` folder.

All programs should be run from the root folder of the project.
All python requirements are provided in the `requirements.txt` file.
You need to install those tools to run the program:
- `docker` - run containers and retrieve SBOM files from Docker Scout;
- `bom` - generate SBOM files from Docker containers;
- `trivy` - generate SBOM files from Docker containers;
- `syft` - generate SBOM files from Docker containers;
- `sbomqs` - generate SBOM scores;
- `ghcr.io/google/osv-scanner` - docker container to generate OSV files;