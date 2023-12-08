import asyncio
import os
import hashlib


CHUNK_SIZE = 1024 * 1024


def get_md5_hash(filename):
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            md5_hash.update(chunk)
        return md5_hash


async def get_files_list(root_dir: str) -> list[str]:
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


async def files_to_remove(root_dir: str) -> list[str]:
    remove_files = []
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.startswith("score."):
                remove_files.append(os.path.join(root, file))
            elif file.startswith("osv."):
                remove_files.append(os.path.join(root, file))
            continue
    return remove_files


async def remove_empty_dirs(root_dir: str):
    for root, dirs, files in os.walk(root_dir):
        if not dirs and not files:
            os.rmdir(root)


async def main():
    root_dir = os.path.abspath("sbom_storage_dir")
    # get all the files in the root_dir and its subdirectories
    all_files = await get_files_list(root_dir)

    # calculate file hashes
    file_hashes = {}
    for file in all_files:
        file_hashes[file] = get_md5_hash(file).hexdigest()

    # locate duplicates
    duplicates = {}
    for file, hash in file_hashes.items():
        if hash not in duplicates:
            duplicates[hash] = [file]
        else:
            duplicates[hash].append(file)

    # delete duplicates except the first one
    for hash, files in duplicates.items():
        if len(files) == 1:
            continue
        for file in files[1:]:
            os.remove(file)

    # get files to remove
    remove_files = await files_to_remove(root_dir)
    # remove files
    for file in remove_files:
        os.remove(file)

    # remove empty directories
    await remove_empty_dirs(root_dir)
    return 0


if __name__ == "__main__":
    asyncio.run(main())
