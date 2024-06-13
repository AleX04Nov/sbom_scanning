# Installation

### Python Requirements
Install all packages from the requirements.txt file by running the following command:

```pip install -r requirements.txt```

### SBOM Analysis tools

#### OSV-scanner
OSV-scanner is a tool for scanning Software Bill of Materials (SBOM) in both CycloneDX and SPDX formats and output vulnerability information based on those files.

```
go install github.com/google/osv-scanner/cmd/osv-scanner@v1
```

#### CycloneDX-cli
CycloneDX-cli is a tool for validating a Software Bill of Materials (SBOM) in CycloneDX format.

```
wget https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.25.1/cyclonedx-linux-x64 && sudo mv ./cyclonedx-linux-x64 /usr/local/bin/cyclonedx && chmod +x /usr/local/bin/cyclonedx
```

#### SBOMQS
SBOMQS is a tool that can be used to create a score for a Software Bill of Materials (SBOM) in both CycloneDX and SPDX formats.

```
wget https://github.com/interlynk-io/sbomqs/releases/download/v0.1.4/sbomqs-linux-amd64 && sudo mv ./sbomqs-linux-amd64 /usr/local/bin/sbomqs && chmod +x /usr/local/bin/sbomqs
```

#### SBOM-utility
SBOM-utility is an official CycloneDX tool for validating a Software Bill of Materials (SBOM) in both CycloneDX and SPDX formats but only in JSON.

```
wget https://github.com/CycloneDX/sbom-utility/releases/download/v0.16.0/sbom-utility-v0.16.0-linux-amd64.tar.gz && tar -C /usr/local/bin -xzf ./sbom-utility-v0.16.0-linux-amd64.tar.gz sbom-utility && rm ./sbom-utility-v0.16.0-linux-amd64.tar.gz
```

#### SPDX-tools
SPDX-tools is an official SPDX tool that can be used to validate a Software Bill of Materials (SBOM) in SPDX format.

```
pip install spdx-tools
```

#### NTIA conformance checker
NTIA conformance checker is an official SPDX tool that can be used to validate a Software Bill of Materials (SBOM) in SPDX format.

```
pip install ntia-conformance-checker
```

# Usage
In order to use the SBOM analysis tools, you need to have a Software Bill of Materials (SBOM) in either CycloneDX or SPDX format. The following commands can be used to run the tools:
- `main.py` - do the creation of data folder (`data_TIMESTAMP`) and gathers information on where to find the SBOM files on the internet and their type (`SPDX`, `CycloneDX`, `XML`, `JSON`, `Tag/Value`, `YAML`);
- `download_sboms_10.py` - download the SBOM files from the internet, based on the list from the main stage;
- `sbom_external_assesment_11.py` - do the external assessment of the SBOM files with Third party and official tools (`osv-scanner`, `sbomqs`, etc.);
- `sum_up_csv_12.py` - do the manual analysis and compile this data with an external assessment. After, do the summarization of the external assessment of the SBOM files. Output data in 2 files. Those files were used as a data source for our paper. And were described in our paper: 
  - `sbom_list.csv`
  - `dependency_list.json`;

You can also find a lot of other python files, which are named `XX_NUMBER.py`. These modules are used in the `main.py` . But the last three files (10, 11, 12) need to be run manually.

# Jupyter Analysis Scripts

You can find our jupyter analysis scripts in the `jupyter_scripts` folder. These scripts are used to analyze the data gathered by the main script. The script's name is `analysis.ipynb` and this script is used to analyze the data from the `sbom_list.csv` and `dependency_list.csv` files.

# Misc
In the `data_TIMESTAMP` folder, you can find all intermediate files created during the process. These files feed information between the modules and are indented for better human readability.