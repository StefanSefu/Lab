MAX_HTTP_SIZE = 10_000_000 # safety cap (10 MB)

def recv_more(sock) -> bytes:
    chunk = sock.recv(4096)
    if not chunk:
        raise RuntimeError("Connection closed mid-chunked response")
    return bytes(chunk)

def read_exact(sock, n) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(min(4096, n - len(out)))
        if not chunk:
            raise RuntimeError("Connection closed mid-chunked response")
        out.extend(chunk)
        if len(out) > MAX_HTTP_SIZE:
            raise RuntimeError("Response exceeded MAX_HTTP_SIZE")
    return bytes(out)

def read_until(sock, marker: bytes) -> bytes:
    out = bytearray()
    while marker not in out:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed mid-chunked response")
        out.extend(chunk)
        if len(out) > MAX_HTTP_SIZE:
            raise RuntimeError("Response exceeded MAX_HTTP_SIZE")
    return bytes(out)

def read_already_until(sock, already: bytes, marker: bytes) -> bytes:
    out = bytearray(already)
    while marker not in out:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed mid-chunked response")
        out.extend(chunk)
        if len(out) > MAX_HTTP_SIZE:
            raise RuntimeError("Response exceeded MAX_HTTP_SIZE")
    return bytes(out)

def read_line_from_buffer_and_sock(sock, buffer: bytearray) -> bytes:
    """
    Read a line ending with \r\n from buffer and sock. It also removes the line from buffer.

    :param sock: socket to read from if buffer is insufficient
    :param buffer: bytearray buffer to read from
    :return: line without \r\n
    """
    while True:
        p = buffer.find(b"\r\n")
        if p != -1:
            line = bytes(buffer[:p])
            del buffer[:p + 2]
            return line
        buffer.extend(recv_more(sock))
        if len(buffer) > MAX_HTTP_SIZE:
            raise RuntimeError("Response exceeded MAX_HTTP_SIZE")

def read_n_from_buffer_and_sock(sock, buffer: bytearray, n: int) -> bytes:
    """
    Read exactly n bytes from buffer and sock. It also removes the bytes from buffer.

    :param sock: socket to read from if buffer is insufficient
    :param buffer: bytearray buffer to read from
    :param n: number of bytes to read
    :return: the bytes read
    """
    while len(buffer) < n:
        buffer.extend(recv_more(sock))
        if len(buffer) > MAX_HTTP_SIZE:
            raise RuntimeError("Response exceeded MAX_HTTP_SIZE")
    data = bytes(buffer[:n])
    del buffer[:n]
    return data

def read_chunked_raw(sock, already: bytes) -> bytes:
    # Chunked body looks like this:
    # <chunk-size in hex>;extension=test\r\n            # ';extension=test' is optional
    # <chunk-data>\r\n
    # <chunk-size in hex>;extension=test\r\n            # ';extension=test' is optional
    # <chunk-data>\r\n
    # ...
    # 0\r\n
    # <trailer-header1>: value\r\n
    # <trailer-header2>: value\r\n
    # ...\r\n
    # \r\n

    buffer = bytearray(already)
    out = bytearray()

    while True:
        size_line = read_line_from_buffer_and_sock(sock, buffer).strip()
        if not size_line:
            continue # blank lines like this should not exist, but ignore them

        # ignore chunk extensions: "<chunk-size>;foo=bar\r\n"
        size_b = size_line.split(b";", 1)[0]
        try:
            size = int(size_b, 16) # chunk size is in hex
        except ValueError:
            raise RuntimeError(f"Bad chunk size line: {size_b}")

        if size == 0:
            # We are at trailers, read them until empty line
            while True:
                line = read_line_from_buffer_and_sock(sock, buffer)
                if line == b"":
                    return bytes(out)

        out.extend(read_n_from_buffer_and_sock(sock, buffer, size))

        # consume the '\r\n' after the chunk data
        if read_n_from_buffer_and_sock(sock, buffer, 2) != b"\r\n":
            raise RuntimeError("Malformed chunk: missing '\\r\\n' after data")

        if len(out) > MAX_HTTP_SIZE:
            raise RuntimeError("Response exceeded MAX_HTTP_SIZE")

def parse_headers(header_block: bytes):
    lines = header_block.split(b"\r\n")
    first_line = lines[0]

    headers = {}
    for line in lines[1:]:
        if not line or b":" not in line:
            continue
        k, v = line.split(b":", 1)
        headers[k.strip().lower()] = v.strip()
        
    return first_line, headers

def read_full_http_request(client_sock):
    head = read_until(client_sock, b"\r\n\r\n")
    if b"\r\n\r\n" not in head:
        raise RuntimeError("Incomplete HTTP request headers")

    header_block, rest = head.split(b"\r\n\r\n", 1)
    request_first_line, headers = parse_headers(header_block)
    #method, path, version = request_first_line.split(" ", 2) # if we would like these details: method, path, version

    # body (Content-Length only)
    content_length = int(headers.get(b"content-length", b"0"))
    # We might have already read a part of the body
    body = bytearray(rest)
    while len(body) < content_length:
        chunk = client_sock.recv(4096)
        if not chunk:
            break
        body.extend(chunk)

    return request_first_line, headers, bytes(body)

def read_full_http_response(upstream_sock):
    head = read_until(upstream_sock, b"\r\n\r\n")

    header_part, rest = head.split(b"\r\n\r\n", 1)

    status_line, headers = parse_headers(header_part)

    te = headers.get(b"transfer-encoding", b"").lower()
    cl = headers.get(b"content-length")

    # case 1: check for 'chunked'
    if b"chunked" in te:
        # Need raw chunked bytes (rest + everything until end of trailers)
        body = read_chunked_raw(upstream_sock, rest)
        return status_line, headers, body

    # case 2: check for 'content-length' (no chunked)
    if cl is not None:
        try:
            length = int(cl)
        except ValueError:
            length = None

        if length is not None:
            remaining = max(0, length - len(rest))
            body = rest + (read_exact(upstream_sock, remaining) if remaining else b"")
            return status_line, headers, body

    # case 3: read until close (no content-length, no chunked)
    body = bytearray(rest)
    while True:
        chunk = upstream_sock.recv(4096)
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > MAX_HTTP_SIZE:
            raise RuntimeError("Response exceeded MAX_HTTP_SIZE")
        
    return status_line, headers, bytes(body)