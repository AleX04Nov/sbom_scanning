# (?i)(^.*(sbom|spdx|cyclondex|cdx|bom)(\.json|\.xml|\.yaml|\.yml|\.sbom))|(^.*(\.json|\.xml|\.yaml|\.yml|\.sbom)(.sbom|.spdx|.cyclondex|.cdx|.bom)).*$
# context:global content:^\"bomFormat\".*$ file:/(^.*(^.*(sbom|spdx|cyclondex|cdx|bom)(\.json|\.xml|\.yaml|\.sbom))|(^.*(\.json|\.xml|\.yaml|\.sbom)(.sbom|.spdx|.cyclondex|.cdx|.bom))).*$/ -file:^.*(example|test|utf|sample|playground|\.gobom.json|fake|\.gz).*$  archived:yes fork:yes  count:2000 -repo:^github\.com/pineappleEA/pineapple-src$ -repo:^github\.com/chains-project/SBOM-2023$ -repo:^github\.com/adempiere/adempiere$
# apache/airflow-site - a lot of sboms
import os
import shutil
from collections.abc import Coroutine
from typing import Any

import aiofiles
import aiohttp
import asyncio
import json


aio_session: aiohttp.ClientSession


async def sourcegraph_get_sboms(query: str) -> list:
    result = []
    headers = {
        'Accept': 'text/event-stream',
    }
    url = "https://sourcegraph.com/.api/search/stream"
    params = {
        'q': query,
    }
    aio_session.chunk_size = 1024 ** 3
    async with aio_session.request(method='get', url=url, headers=headers, params=params) as resp:
        match_event = False
        resp.content._high_water *= 128
        async for line in resp.content:
            if line == b'event: matches\n':
                match_event = True
                continue
            if match_event:
                match_data = line[len('data: '):].decode('utf-8').strip()
                result += json.loads(match_data)
                match_event = False
    return result


async def github_download_raw_file(repo_name: str, commit: str, path: str, output_path: str = None) -> bool:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    url = f'https://raw.githubusercontent.com/{repo_name}/{commit}/{path}'
    async with aio_session.request(method='get', url=url) as resp:
        if resp.status != 200:
            Exception(f"Failed to download {url}")
        async with aiofiles.open(output_path, 'wb') as f:
            # 1mb chunks
            async for chunk in resp.content.iter_chunked(1024 ** 3):
                await f.write(chunk)



async def main():
    global aio_session
    aio_session = aiohttp.ClientSession()

    # alloc constants
    sourcegraph_root_dir = os.path.abspath("sbom_storage_dir/sourcegraph/")
    # spdx 2.1
    # spdx tags
    # cyclonedx: json, xml
    query_dict = {
        'spdx_2_spdx': 'context:global SPDXID: SPDXRef-DOCUMENT file:\.spdx$ -file:^.*(example|test|utf|sample|playground|manifest\.|\.gobom.json|fake|\.gz|expected|schema|config\.|demo|tutorial).*$ -repo:^.*(example).*$ -repo:^github\.com(/pineappleEA/pineapple-src|/chainguard-dev/bom-shelter|/Open-Source-Compliance/package-analysis|/guacsec/guac-data|/adempiere/adempiere|/chains-project/SBOM-2023|/apache/airflow-site)$ archived:yes fork:yes count:5000',
        'spdx_2_1_json': 'context:global SPDXVersion AND SPDX-2.1 file:\.json -file:^.*(example|test|utf|sample|playground|\.gobom.json|fake|\.gz|expected|schema|config\.|demo|tutorial).*$ -repo:^.*(example).*$ -repo:^github\.com(/pineappleEA/pineapple-src|/chainguard-dev/bom-shelter|/Open-Source-Compliance/package-analysis|/guacsec/guac-data|/adempiere/adempiere|/chains-project/SBOM-2023|/apache/airflow-site)$ archived:yes fork:yes count:5000',
        'spdx_2_2_json': 'context:global SPDXVersion AND SPDX-2.2 file:\.json -file:^.*(example|test|utf|sample|playground|\.gobom.json|fake|\.gz|expected|schema|config\.|demo|tutorial).*$ -repo:^.*(example).*$ -repo:^github\.com(/pineappleEA/pineapple-src|/chainguard-dev/bom-shelter|/Open-Source-Compliance/package-analysis|/guacsec/guac-data|/adempiere/adempiere|/chains-project/SBOM-2023|/apache/airflow-site)$ archived:yes fork:yes count:5000',
        'spdx_2_3_json': 'context:global SPDXVersion AND SPDX-2.3 file:\.json -file:^.*(example|test|utf|sample|playground|\.gobom.json|fake|\.gz|expected|schema|config\.|demo|tutorial).*$ -repo:^.*(example).*$ -repo:^github\.com(/pineappleEA/pineapple-src|/chainguard-dev/bom-shelter|/Open-Source-Compliance/package-analysis|/guacsec/guac-data|/adempiere/adempiere|/chains-project/SBOM-2023|/apache/airflow-site)$ archived:yes fork:yes count:5000',
        'cyclonedx_xml': 'context:global xmlns="http://cyclonedx.org/schema/bom/ file:\.xml -file:^.*(example|test|utf|playground|\.gobom.json|fake|\.gz|expected|schema|config\.|demo|tutorial).*$ -repo:^.*(example).*$ -repo:^github\.com(/pineappleEA/pineapple-src|/chainguard-dev/bom-shelter|/Open-Source-Compliance/package-analysis|/guacsec/guac-data|/adempiere/adempiere|/chains-project/SBOM-2023|/apache/airflow-site)$ archived:yes fork:yes count:5000',
        'cyclonedx_json': 'context:global bomFormat and CycloneDX file:\.json -file:^.*(example|test|utf|playground|\.gobom.json|fake|\.gz|expected|schema|config\.|demo|tutorial).*$ -repo:^.*(example).*$ -repo:^github\.com(/pineappleEA/pineapple-src|/chainguard-dev/bom-shelter|/Open-Source-Compliance/package-analysis|/guacsec/guac-data|/adempiere/adempiere|/chains-project/SBOM-2023|/apache/airflow-site)$ archived:yes fork:yes count:5000'
    }
    sbom_dict = {}

    # clear the target directory if it exists
    if os.path.exists(sourcegraph_root_dir):
        shutil.rmtree(sourcegraph_root_dir)
    print("Successfully cleared the target directory")

    # get the sbom urls
    for query_name in query_dict.keys():
        query = query_dict[query_name]
        sbom_dict[query_name] = await sourcegraph_get_sboms(query)
        print(f"Successfully got the SBOM urls for `{query_name}` . Total: {len(sbom_dict[query_name])}")

    # download the SBOMs
    for sbom_name in sbom_dict.keys():
        sbom_list = sbom_dict[sbom_name]
        for sbom in sbom_list:
            if sbom['repository'][:11] != 'github.com/':
                # Exception("Not github.com")
                print(f"Skipping {sbom['repository'], sbom['commit'], sbom['path']}")
                continue
            repo_name = sbom["repository"][11:]
            sbom_filename = sbom['path'].translate(str.maketrans('/', '_'))
            sbom_path = os.path.join(sourcegraph_root_dir, sbom_name, repo_name, sbom_filename)
            await github_download_raw_file(repo_name, sbom["commit"], sbom["path"], sbom_path)
        print(f"Successfully downloaded the SBOMs for `{sbom_name}`")
    print("Successfully downloaded all the SBOMs")


    # close aio session
    await aio_session.close()


if __name__ == '__main__':
    asyncio.run(main())
