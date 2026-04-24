import hashlib


def generate_file_hash(file_stream):
    sha256 = hashlib.sha256()

    for chunk in iter(lambda: file_stream.read(4096), b""):
        sha256.update(chunk)

    file_stream.seek(0)
    return sha256.hexdigest()
