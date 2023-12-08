import asyncio
import json
import os
import subprocess


first_sbomqs_run = True

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


def generate_sbomqs_scores(sbom_path: str, output_filename: str) -> bool:
    global first_sbomqs_run
    """Create and store a sbomqs scores.

    Args:
        sbom_path (str) - path to the sbom file
        output_filename (str) - path to a location for storing output

    Returns:
        Result as a boolean
    """
    try:
        with open(output_filename, 'w') as outfile:
            if first_sbomqs_run:
                env = os.environ.copy()
                first_sbomqs_run = False
            else:
                env = os.environ.copy()
                env["INTERLYNK_DISABLE_VERSION_CHECK"] = "1"

            result = subprocess.run(
                [
                    "sbomqs",
                    "score",
                    "--json",
                    sbom_path,
                ],
                stdout=outfile,
                stderr=subprocess.STDOUT,
                check=True,
                env=env
            )
        # rewrite field ["files"][]["file_name"] to be left only with the last 2 directories
        # to hide the real username of the pc
        with open(output_filename, 'r') as outfile:
            try:
                data = json.load(outfile)
            except json.decoder.JSONDecodeError:
                # if first line begins with "failed to parse" then the file is empty
                # set caret to the beginning of the file
                outfile.seek(0)
                if outfile.readline().startswith("failed to parse"):
                    data = {}
                # re-raise the exception
                else:
                    raise
        # if data not empty
        if data:
            for file in data["files"]:
                file["file_name"] = "/" + "/".join(file["file_name"].split("/")[-3:])
        # rewrite the file
        with open(output_filename, 'w') as outfile:
            json.dump(data, outfile, indent=4)
    except subprocess.CalledProcessError:
        return False
    return True


async def main():
    root_dir = os.path.abspath("sbom_storage_dir/")
    # get all the files in the root_dir and its subdirectories
    all_files = get_files_list(root_dir)

    file_num = 0
    for file in all_files:
        # print progress
        file_num += 1
        print(f"Processing file {file_num} of {len(all_files)}")
        # add `score.` prefix to the filename
        output_filename = os.path.join(os.path.dirname(file), 'score.' + os.path.basename(file))
        # if file extension is not .json, append .json to the filename
        if not output_filename.endswith('.json'):
            output_filename += '.json'
        generate_sbomqs_scores(file, output_filename)
    return 0


if __name__ == "__main__":
    asyncio.run(main())
