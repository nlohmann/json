import hashlib
from path import Path 
import sys


def file_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as opened_file:
        for chunk in iter(lambda: opened_file.read(4096), b""):
            sha256.update(chunk)
        return sha256.hexdigest()


def file_hashes(root_dir):
    ret = []
    for subdir in root_dir.walkdirs():
        for f in subdir.files():
            sha = file_sha256(f)
            ret.append((f, sha))
    return ret


def create_external_data(srcpath, dstdir, sha):
    segments = srcpath.splitall()
    external_data_path = dstdir.joinpath(*segments[2:-1])
    external_data_path.makedirs_p()
    external_data_file = external_data_path / sha
    srcpath.copyfile(external_data_file)


def create_link(filepath, dstdir, sha):
    newpath = dstdir / filepath.with_suffix(filepath.ext + ".sha256")
    newpath.dirname().makedirs_p()
    with open(newpath, "w") as f:
        f.write(sha)


def main(root_dir):
    hashes = file_hashes(root_dir)
    external_data_dir = Path("external_data") / "json" / "SHA256"
    external_data_dir.makedirs_p()
    links_dir = Path("links").mkdir_p()

    for path, sha in hashes:
        create_external_data(path, external_data_dir, sha)
        create_link(path, links_dir, sha)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
