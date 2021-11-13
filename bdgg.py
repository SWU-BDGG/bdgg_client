#!/usr/bin/env python3
import os
import sys
import gzip
import json
import time
import uuid
import struct
import requests
from io import BytesIO
from hashlib import sha256
from collections import namedtuple
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit, parse_qs, urlunsplit

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

BDGG = namedtuple("BDGG", ("version", "uuid", "ext", "runnable", "data"))


class BDGGError(Exception):
    pass


def btoi(data, endian="big"):
    return int.from_bytes(data, endian)


def itob(n, length=1, endian="big"):
    return int.to_bytes(n, length, endian)


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


def dec_sha(data, hexkey, hexiv):
    key = bytes.fromhex(hexkey)
    iv = bytes.fromhex(hexiv)

    cipher = AES.new(
        key=key,
        mode=AES.MODE_CBC,
        iv=iv
    )

    data = cipher.decrypt(data)

    return unpad(
        padded_data=data,
        block_size=AES.block_size,
        style="pkcs7"
    )


class BDGGServer:
    def __init__(self, protocol, baseurl, fileid, token):
        self.protocol = protocol
        self.baseurl = baseurl
        self.fileid = fileid
        self.headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "BDGG-Client v0"
        }

    def geturl(self, path, query={}):
        qrstr = "&".join([f"{x}={y}" for x, y in query.items()])
        url = urlunsplit((self.protocol, self.baseurl, path, qrstr, ""))
        return url

    def request_key(self):
        requrl = self.geturl("/api/v1/key", {"file_id": self.fileid})
        r = requests.get(requrl, headers=self.headers)

        try:
            data = r.json()
        except json.JSONDecodeError:
            raise BDGGError("Malformed response from the server")
    
        if r.status_code != 200:
            code = data['error']['code']
            message = data['error']['message']
            raise BDGGError(r.status_code, code, message)
    
        file = data['data']['file']
        key = data['data']['key']
    
        return file, key

    def download_file(self):
        requrl = self.geturl(f"/download/{self.fileid}")
        r = requests.get(requrl, headers=self.headers)

        if r.status_code != 200:
            data = r.json()
            code = data['error']['code']
            message = data['error']['message']
            raise BDGGError(r.status_code, code, message)

        return r


class BDGGHandler:
    @classmethod
    def on_filedownload(cls, raw_uuid, token, host, protocol):
        raw_uuid = raw_uuid[0]
        token = token[0]
        host = host[0]
        protocol = protocol[0]

        try:
            fileid = uuid.UUID(raw_uuid)
        except ValueError:
            raise BDGGError("Malformed UUID")

        if protocol not in ["http", "https"]:
            raise BDGGError("Invalid protocol")

        server = BDGGServer(protocol, host, fileid, token)

        file, key = server.request_key()
        r = server.download_file()

        bdgg = parse_bdgg(BytesIO(r.content))
        decdata = dec_sha(bdgg.data, key['key'], key['iv'])

        if sha256(decdata).hexdigest() != file['sha256']:
            raise BDGGError("SHA256 hash mismatch!")

        tf = NamedTemporaryFile(suffix="."+bdgg.ext)
        tf.file.write(decdata)

        if bdgg.runnable:
            runnable = bdgg.runnable.format(tf.name)
        else:
            runnable = "xdg-open {}".format(tf.name)

        os.system(runnable)

        time.sleep(1)

    @classmethod
    def handle(cls, url):
        event, query = cls.parse(url)

        if query.get("uuid") is not None:
            query['raw_uuid'] = query['uuid']
            del query['uuid']

        handler = getattr(cls, f"on_{event.lower()}", None)

        if handler is None:
            raise BDGGError("Unknown request type")

        try:
            handler(**query)
        except (TypeError, IndexError):
            raise BDGGError("Malformed request")

    @staticmethod
    def parse(url):
        split = urlsplit(url)
        if split.scheme != "swubdgg":
            raise BDGGError("Protocol Mismatch!")

        event = split.netloc
        query = parse_qs(split.query)

        return event, query


def main():
    url = sys.argv[1]
    BDGGHandler.handle(url)
    exit()


if __name__ == "__main__":
    main()
