#!/usr/bin/env python3
import os
import sys
import gzip
import uuid
import struct
from textwrap import dedent
from collections import namedtuple
from tempfile import NamedTemporaryFile

BDGG = namedtuple("BDGG", ("version", "uuid", "ext", "runnable", "data"))


class BDGGError(Exception):
    pass


def pack_bdgg(version, uuid, ext, runnable, data):
    if runnable is None:
        runnable = ""
    ext_len = len(ext)
    runnable_len = len(runnable)
    data_comp = gzip.compress(data)
    data_len = len(data_comp)
    bdgg_format = f">3sc16sc{ext_len}sc{runnable_len}s{data_len}s"

    resbytes = struct.pack(
        bdgg_format,
        b"BDG",
        itob(version),
        uuid.bytes,
        itob(ext_len),
        ext.encode(),
        itob(runnable_len),
        runnable.encode(),
        data_comp
    )

    return resbytes


def parse_bdgg(fp):
    header = fp.read(3)

    if header != b"BDG":
        raise BDGGError("Magic Mismatch")
    pass

    version = btoi(fp.read(1))
    uuid_raw = fp.read(16)
    uuid_obj = uuid.UUID(bytes=uuid_raw)
    ext_len = btoi(fp.read(1))
    ext = fp.read(ext_len).decode()
    runnable_len = btoi(fp.read(1))
    runnable = fp.read(runnable_len).decode()
    data_comp = fp.read()
    data = gzip.decompress(data_comp)

    return BDGG(version, uuid_obj, ext, runnable, data)


def btoi(data, endian="big"):
    return int.from_bytes(data, endian)


def itob(n, length=1, endian="big"):
    return int.to_bytes(n, length, endian)


def main():
    cmdname = sys.argv[0]
    HELP = dedent(f"""
        Usage: {cmdname} OPTION filename

        Option can be one of the followings:
          encrypt:
            encrypt the given file to BDGG format.
          decrypt:
            decrypt the given file to original file.
    """)
    args = sys.argv[1:]

    if len(args) != 2:
        print(HELP)
        exit()

    opt = args[0]
    filename = args[1]

    if opt == "encrypt":
        enc(filename)
    elif opt == "decrypt":
        dec(filename)
    else:
        print(HELP)
    exit()


def enc(filename):
    data = open(filename, "rb").read()
    uuid_obj = uuid.uuid4()
    print(f"UUID is: {uuid_obj}")
    ext = "." + filename.rsplit(".", 1)[-1]
    runnable = input("Please enter the runnable command: ")

    bdgg_enc = pack_bdgg(0, uuid_obj, ext, runnable, data)

    with open(f"enc_{filename}.bdgg", "wb") as f:
        f.write(bdgg_enc)

    print("File encrypted at:", f"enc_{filename}.bdgg")


def dec(filename):
    fp = open(filename, "rb")
    bdgg = parse_bdgg(fp)

    print(f"UUID is: {bdgg.uuid}")

    tf = NamedTemporaryFile(suffix=bdgg.ext)
    tf.file.write(bdgg.data)

    runnable = bdgg.runnable.format(tf.name)
    print(f"running `{runnable}`...")
    os.system(runnable)

    print("Done!")


if __name__ == "__main__":
    main()
