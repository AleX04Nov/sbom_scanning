import asyncio
import os

import docker
from docker import DockerClient


docker_client: DockerClient


# ignoring files that starts with "score." or "osv." and ends with ".tar" or ".DS_Store"
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


def run_osv_scanner_on_sbom(target_dir: str, sbom_filename: str, output: str = 'scan-results.json'):
    dirs_mapping = {
        os.path.abspath(target_dir): {'bind': '/src', 'mode': 'rw'}
    }
    try:
        docker_client.containers.run(
            image="ghcr.io/google/osv-scanner",
            remove=True,
            detach=False,
            volumes=dirs_mapping,
            command=f"--format json --sbom=/src/{sbom_filename} --output /src/{output}"
        )
    except docker.errors.ContainerError as e:
        if e.exit_status == 1:
            return True
        elif e.exit_status == 128:
            return False
        return False
    return True


def main():
    global docker_client

    # init global variables
    docker_client = docker.from_env()
    root_dir = os.path.abspath("sbom_storage_dir/sourcegraph")

    # get all the files in the root_dir and its subdirectories
    all_files = get_files_list(root_dir)

    file_num = 0
    for file in all_files:
        # print progress
        file_num += 1
        print(f"Processing file {file_num} of {len(all_files)}")
        # add `score.` prefix to the filename
        output_filename = os.path.join(os.path.dirname(file), 'osv.' + os.path.basename(file))
        # if file extension is not .json, append .json to the filename
        if not output_filename.endswith('.json'):
            output_filename += '.json'
        # get directory of the file
        file_dir = os.path.dirname(file)
        # get only the filename without the directory
        file = os.path.basename(file)
        output_filename = os.path.basename(output_filename)
        if not run_osv_scanner_on_sbom(file_dir, file, output_filename):
            # open output file and write empty json
            with open(os.path.join(file_dir, output_filename), 'w') as outfile:
                outfile.write("{}")
    return 0


if __name__ == "__main__":
    main()
