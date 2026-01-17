import socket
import threading

HOP_BY_HOP = {
    b"connection",
    b"proxy-connection",
    b"keep-alive",
    b"transfer-encoding",
    b"te",
    b"trailers",
    b"upgrade",
}

def read_until(sock, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def parse_headers(header_bytes: bytes):
    lines = header_bytes.split(b"\r\n")
    req_line = lines[0].decode("iso-8859-1")
    method, path, version = req_line.split(" ", 2)

    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        k, v = line.split(b":", 1)
        headers[k.strip().lower()] = v.strip()

    return method, path, version, headers

def handle_client(client_sock: socket.socket):
    try:
        head = read_until(client_sock, b"\r\n\r\n")
        if b"\r\n\r\n" not in head:
            return

        header_part, rest = head.split(b"\r\n\r\n", 1)
        method, path, version, headers = parse_headers(header_part)

        host = headers.get(b"host")
        if not host:
            return
        host = host.decode("iso-8859-1")

        # body (Content-Length only for simplicity)
        content_length = int(headers.get(b"content-length", b"0"))
        body = rest
        while len(body) < content_length:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            body += chunk

        # connect to upstream server
        upstream = socket.create_connection((host.split(":")[0], 80), timeout=10)

        # rebuild request, stripping hop-by-hop headers
        out_lines = [f"{method} {path} {version}".encode("iso-8859-1")]
        for k, v in headers.items():
            if k in HOP_BY_HOP:
                continue
            out_lines.append(k + b": " + v)

        # keep it simple: close after response
        out_lines.append(b"Connection: close")
        out_req = b"\r\n".join(out_lines) + b"\r\n\r\n" + body

        upstream.sendall(out_req)

        # stream response back to client (this is the key part)
        while True:
            resp_chunk = upstream.recv(4096)
            if not resp_chunk:
                break
            client_sock.sendall(resp_chunk)

        upstream.close()

    finally:
        client_sock.close()

def serve(host="127.0.0.1", port=8080):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(200)
    print(f"Proxy listening on {host}:{port}")

    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    serve()