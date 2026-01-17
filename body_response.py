import gzip
import zlib
import brotli

def decompress_body_using_content_encoding(body: bytes, headers: dict) -> bytes:
    enc = headers.get(b"content-encoding", b"").lower()

    if enc == b"gzip":
        return gzip.decompress(body)

    if enc == b"deflate":
        return zlib.decompress(body)

    if enc == b"br":
        return brotli.decompress(body)

    return body # no enconding

def compress_body_using_content_encoding(body: bytes, headers: dict) -> bytes:
    enc = headers.get(b"content-encoding", b"").lower()

    if enc == b"gzip":
        return gzip.compress(body)

    if enc == b"deflate":
        # zlib wrapper (matches most servers)
        return zlib.compress(body)

    if enc == b"br":
        return brotli.compress(body)

    return body  # no encoding

def get_charset(headers: dict) -> str:
    ct = headers.get(b"content-type", b"").decode("iso-8859-1")
    if "charset=" in ct:
        return ct.split("charset=", 1)[1].split(";", 1)[0].strip()
    return "utf-8" # default charset

def decode_body_using_content_type_charset(body: bytes, headers: dict) -> str:
    charset = get_charset(headers)
    return body.decode(charset, errors="replace")

def encode_body_using_content_type_charset(text: str, headers: dict) -> bytes:
    charset = get_charset(headers)
    return text.encode(charset, errors="replace")