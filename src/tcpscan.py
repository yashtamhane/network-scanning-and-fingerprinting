#!/usr/bin/env python3

import argparse
import sys
import re
import socket
import ssl

TLS_LIKELY_PORTS = {443, 853, 993, 465, 8443}

def parse_args():
    parser = argparse.ArgumentParser(description="Simple TCP connect scanner and service fingerprinting tool.")
    parser.add_argument("-p", metavar="port_range", help="Port or port range to scan (e.g., 80 or 20-100)")
    parser.add_argument("target", help="Target IP address or hostname to scan")
    return parser.parse_args()

def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def is_ip_address(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except socket.error:
        return False

def validate_port_range(port_str):
    if re.match(r"^\d+$", port_str):  # single port
        return 0 <= int(port_str) <= 65535
    elif re.match(r"^\d+-\d+$", port_str):  # port range
        start, end = map(int, port_str.split('-'))
        return 0 <= start <= end <= 65535
    return False

def get_ports_to_scan(p_arg):
    DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080]
    if p_arg is None:
        return DEFAULT_PORTS
    if '-' in p_arg:
        start, end = map(int, p_arg.split('-'))
        return list(range(start, end + 1))
    else:
        return [int(p_arg)]

def connect_scan(ip: str, ports: list[int], timeout: int = 1) -> list[int]:
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    return open_ports

def sanitize_output(data: bytes) -> str:
    # Replacing non-printable bytes with '.'
    return ''.join(chr(b) if (32 <= b <= 126 or b in (10, 13)) else '.' for b in data)

def fingerprint_tcp_service(ip: str, port: int, timeout: int = 3) -> tuple[int, str]:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)

        # (1) TCP server-initiated
        try:
            banner = s.recv(1024)
            if banner:
                s.close()
                return (1, sanitize_output(banner))
        except socket.timeout:
            pass

        # (2) HTTP GET request
        try:
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            response = s.recv(1024)
            if response:
                s.close()
                return (3, sanitize_output(response))
        except:
            pass

        # (3) Generic TCP probe
        try:
            s.sendall(b"\r\n\r\n\r\n\r\n")
            response = s.recv(1024)
            if response:
                s.close()
                return (5, sanitize_output(response))
        except:
            pass

        s.close()
        return (5, "")
    except Exception:
        return (0, "")

def fingerprint_tls_service(ip: str, hostname: str | None, port: int, timeout: int = 3) -> tuple[int, str]:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname or None) as ssock:
                ssock.settimeout(timeout)

                # (1) TLS server-initiated
                try:
                    banner = ssock.recv(1024)
                    if banner:
                        return (2, sanitize_output(banner))
                except socket.timeout:
                    pass

                # (2) HTTPS GET
                try:
                    ssock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    response = ssock.recv(1024)
                    if response:
                        return (4, sanitize_output(response))
                except:
                    pass

                # (3) Generic TLS probe
                try:
                    ssock.sendall(b"\r\n\r\n\r\n\r\n")
                    response = ssock.recv(1024)
                    if response:
                        return (6, sanitize_output(response))
                except:
                    return (6, "")

                return (6, "")
    except Exception:
        return (0, "")

# === Main ===

args = parse_args()
ports_to_scan = get_ports_to_scan(args.p)
resolved_ip = resolve_target(args.target)

if not resolved_ip:
    print(f"Error: Unable to resolve hostname '{args.target}'.")
    sys.exit(1)
if args.p and not validate_port_range(args.p):
    print(f"Error: '{args.p}' is not a valid port or port range.")
    sys.exit(1)

print(f"Target IP: {resolved_ip}")
print(f"Port(s): {args.p if args.p else 'Default ports'}")
print(f"Parsed port list: {ports_to_scan}")
print("[*] Starting TCP Connect Scan...\n")

open_ports = connect_scan(resolved_ip, ports_to_scan)
print(f"[+] Open ports: {open_ports}\n")

for port in open_ports:
    port_type = 0
    response = ""

    # Always try TCP first
    tcp_type, tcp_response = fingerprint_tcp_service(resolved_ip, port)

    if tcp_type in {1, 3}:
        port_type = tcp_type
        response = tcp_response
    else:
        # TCP inconclusive -> Try TLS even if port is nonstandard
        tls_hostname = None if is_ip_address(args.target) else args.target
        tls_type, tls_response = fingerprint_tls_service(resolved_ip, tls_hostname, port)

        if tls_type in {2, 4, 6}:
            port_type = tls_type
            response = tls_response
        else:
            port_type = tcp_type
            response = tcp_response

    type_label = {
        1: "(1) TCP server-initiated",
        2: "(2) TLS server-initiated",
        3: "(3) HTTP server",
        4: "(4) HTTPS server",
        5: "(5) Generic TCP server",
        6: "(6) Generic TLS server"
    }.get(port_type, "(?) Unknown")

    print(f"Host: {resolved_ip}:{port}")
    print(f"Type: {type_label}")
    print("Response:")

    if response:
        parts = response.split("\n\n", 1)
        header = parts[0].replace('·', ' ')
        print("\n".join("  " + line.strip() for line in header.split("\n")))
        if len(parts) > 1:
            print()
            html = parts[1].replace('·', ' ')
            print("\n".join("  " + line.strip() for line in html.split(">")))
    else:
        print("  (no response)")

    print()
