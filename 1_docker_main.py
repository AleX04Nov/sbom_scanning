import subprocess

import os
import docker
import requests
from docker import DockerClient

docker_client: DockerClient


def list_rindex(lst, x):
    for r_idx, elt in enumerate(reversed(lst)):
        if elt == x:
            return len(lst) - 1 - r_idx


def get_dir_size(dir_path):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(dir_path):
        for file in filenames:
            file_path = os.path.join(dirpath, file)
            if not os.path.islink(file_path):
                total_size += os.path.getsize(file_path)
    return total_size


# get top popular docker images from docker hub
def get_top_docker_images(count=1000) -> dict:
    resp = requests.request(
        method="GET",
        url="https://hub.docker.com/api/content/v1/products/search",
        params={
            "page_size": count,
            "page": 1,
            "type": "image",
            "q": "",
        },
        headers={
            "Search-Version": "v3",
        }
    )
    resp_json = resp.json()
    return resp_json


def generate_scout_cves(image: str, tag: str, output_filename: str) -> bool:
    """Create and store a SBOM with vulnerabilities list from docker scout.

    Args:
        image (str) - image name, e.g. alpine
        tag (str) - the tag of the image, e.g. latest
        output_filename (str) - path to a location for storing output

    Returns:
        Result as a boolean
    """
    with open(output_filename, 'w') as outfile:
        try:
            result = subprocess.run(
                [
                    "docker",
                    "scout",
                    "cves",
                    "--format",
                    "spdx",
                    "--output",
                    f"{output_filename}",
                    f"{image}:{tag}",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True,
            )
        except subprocess.CalledProcessError:
            return False
    return True


def generate_syft_sbom(image: str, tag: str, output_filename: str) -> bool:
    """Create and store a syft SBOM.

    Args:
        image (str) - image name, e.g. alpine
        tag (str) - the tag of the image, e.g. latest
        output_filename (str) - path to a location for storing output

    Returns:
        Result as a boolean
    """
    try:
        result = subprocess.run(
            [
                "syft",
                "packages",
                "-o",
                "spdx-json",
                "--file",
                output_filename,
                f"{image}:{tag}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
        )
    except subprocess.CalledProcessError:
        return False
    return True


def generate_trivy_sbom(image: str, tag: str, output_filename: str) -> bool:
    """Create and store a trivy SBOM.

    Args:
        image (str) - image name, e.g. alpine
        tag (str) - the tag of the image, e.g. latest
        output_filename (str) - path to a location for storing output

    Returns:
        Result as a boolean
    """
    try:
        result = subprocess.run(
            [
                "trivy",
                "image",
                "--format",
                "spdx-json",
                "--output",
                output_filename,
                f"{image}:{tag}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
        )
    except subprocess.CalledProcessError:
        return False
    return True


def generate_bom_sbom(image: str, tag: str, output_filename: str) -> bool:
    """Create and store a bom SBOM.

    Args:
        image (str) - image name, e.g. alpine
        tag (str) - the tag of the image, e.g. latest
        output_filename (str) - path to a location for storing output

    Returns:
        Result as a boolean
    """
    try:
        result = subprocess.run(
            [
                "bom",
                "generate",
                "--format",
                "json",
                "--output",
                output_filename,
                "--image",
                f"{image}:{tag}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=True,
        )
    except subprocess.CalledProcessError:
        return False
    return True


def generate_sboms_from_docker_image(docker_image_folder_path: str):
    # get the name of the image
    docker_image_name = os.path.basename(os.path.normpath(docker_image_folder_path))

    # load the image from the tar file
    docker_image_tar_path = os.path.join(docker_image_folder_path, f"{docker_image_name}.tar")

    # read tar file as binary data
    with open(docker_image_tar_path, 'rb') as f:
        docker_image_tar_data = f.read()

    # load the image from the binary data
    try:
        images = docker_client.images.load(docker_image_tar_data)
    except requests.exceptions.ConnectionError:
        return

    # get the name of the image from the loaded image
    docker_image_name = (images[0].tags[0])[:images[0].tags[0].index(':')]
    tag = (images[0].tags[0])[images[0].tags[0].index(':') + 1:]

    # generate sboms and scores
    generate_scout_cves(docker_image_name, tag, os.path.join(docker_image_folder_path, 'scout.spdx.json'))
    generate_syft_sbom(docker_image_name, tag, os.path.join(docker_image_folder_path, 'syft.spdx.json'))
    generate_trivy_sbom(docker_image_name, tag, os.path.join(docker_image_folder_path, 'trivy.spdx.json'))
    generate_bom_sbom(docker_image_name, tag, os.path.join(docker_image_folder_path, 'bom.spdx.json'))

    # remove the image back from the docker
    try:
        images[0].remove()
    except docker.errors.APIError:
        pass

    return


def main():
    global docker_client
    docker_root_dir = os.path.abspath("sbom_storage_dir/docker_folder/")

    # create path if not exists
    if not os.path.exists(docker_root_dir):
        os.makedirs(docker_root_dir)

    # init global variables
    docker_client = docker.from_env()
    docker_api = docker_client.api

    # get the top docker images
    top_docker_images = get_top_docker_images()

    index = 1
    print("Downloading the images...")
    # clone them one-by-one onto our machine until we hit free space threshold
    top_docker_images = top_docker_images['summaries'][:1000]
    for image in top_docker_images:
        # Print output
        print(f"{index}/{len(top_docker_images)}; \t{image['name']}")
        index += 1

        # threshold is set to be 10GB
        if (get_dir_size(docker_root_dir) / 1024 / 1024) // 1024 >= 100:
            break
        # check if there is already a tar file for this image
        if not os.path.exists(f"{docker_root_dir}/{image['name'].replace('/', '_')}/{image['name'].replace('/', '_')}.tar"):
            # init var for checking if the image was pulled
            image_pulled = False

            # get an image. And if it not exists - pull it
            try:
                image_instance = docker_client.images.get(f"{image['name']}:latest")
            except docker.errors.ImageNotFound:
                print("Pulling the image: ", image['name'])
                try:
                    docker_client.images.pull(image['name'], tag='latest')
                except docker.errors.APIError:
                    continue
                image_instance = docker_client.images.get(f"{image['name']}:latest")
                image_pulled = True

            # create a directory for the image if it doesn't exist
            dirname = f"{docker_root_dir}/{image['name'].replace('/', '_')}"
            try:
                os.makedirs(dirname)
            except FileExistsError:
                pass

            # save docker image as .tar file
            image_tar_filename = f"{dirname}/{image['name'].replace('/', '_')}.tar"
            image = docker_api.get_image(f"{image['name']}:latest")
            f = open(image_tar_filename, 'wb')
            for chunk in image:
                f.write(chunk)
            f.close()

            # if the image was pulled - remove it
            if image_pulled:
                image_instance.remove()
    print("The images were downloaded successfully.")

    # get the list of subdirectories in the docker_folder root dir
    docker_folders_paths = [os.path.join(docker_root_dir, name) for name in os.listdir(docker_root_dir)
                    if os.path.isdir(os.path.join(docker_root_dir, name))]

    index = 1
    print()
    print("=====================================")
    print("Generating SBOMs...")
    for docker_folder_path in docker_folders_paths:
        # Print output
        print(f"{index}/{len(docker_folders_paths)}; \t{os.path.basename(os.path.normpath(docker_folder_path))}")
        index += 1

        # clean the directory except for the .tar file
        for filename in os.listdir(docker_folder_path):
            if not filename.endswith(".tar"):
                os.remove(os.path.join(docker_folder_path, filename))

        # generate SBOMs and their scores
        generate_sboms_from_docker_image(docker_folder_path)

    print("SBOMs has been generated successfully.")

    return 0


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
