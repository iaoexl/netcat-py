#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Netcat - 模仿 eternallybored.org/misc/netcat 的功能, 并扩展 SSL/TLS + SOCKS5
支持:
  - TCP / UDP 客户端连接
  - TCP / UDP 服务器监听
  - **SSL/TLS 加密客户端与服务端**
  - **SOCKS5 客户端代理** (经代理转发连接目标)
  - **SOCKS5 服务端** (本工具作为代理给其他程序用)
  - 文件上传 / 下载
  - 远程命令执行 (shell)
  - 端口扫描
  - 端口转发 / 代理
  - IPv4 / IPv6
  - 标准输入/输出管道

依赖: 仅标准库 (含 ssl), 纯 Python, 单文件, Windows/Linux/macOS 通用
"""

import argparse
import errno
import ipaddress
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time


VERSION = "1.1.0"
SOCKS5_VERSION = 5

# ============================================================
# 工具函数
# ============================================================

def eprint(*args, **kwargs):
    """错误输出到 stderr"""
    print(*args, file=sys.stderr, **kwargs)


def parse_host(host):
    """解析 host, 返回 (host, port) 或 host"""
    if host is None:
        return None
    if host.startswith('['):
        bracket = host.find(']')
        if bracket != -1:
            h = host[1:bracket]
            rest = host[bracket+1:]
            if rest.startswith(':'):
                return (h, int(rest[1:]))
            return h
    if ':' in host:
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        parts = host.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            return (parts[0], int(parts[1]))
    return host


def parse_ports(port_str):
    """解析端口或范围"""
    ports = set()
    for item in port_str.split(','):
        item = item.strip()
        if not item:
            continue
        if '-' in item:
            a, b = item.split('-', 1)
            for p in range(int(a), int(b) + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(item)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def set_socket_options(sock, opts):
    """根据命令行选项设置 socket 参数"""
    if getattr(opts, 'tcp_nodelay', False) and getattr(opts, 'mode', 'tcp') == 'tcp':
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
    if getattr(opts, 'reuse', True):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
    if getattr(opts, 'ttl', None) is not None:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, opts.ttl)
        except OSError:
            pass
    if getattr(opts, 'send_buffer', None) is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, opts.send_buffer)
        except OSError:
            pass
    if getattr(opts, 'recv_buffer', None) is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, opts.recv_buffer)
        except OSError:
            pass


def socket_type_from_mode(mode):
    return socket.SOCK_DGRAM if mode == 'udp' else socket.SOCK_STREAM


def socket_family_from_host(host, prefer_v6=False):
    if prefer_v6:
        return socket.AF_INET6
    if host is None:
        return socket.AF_INET
    try:
        ip = ipaddress.ip_address(host)
        return socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    except ValueError:
        return None


# ============================================================
# SSL/TLS 辅助
# ============================================================

def ssl_context_client(opts):
    """构建客户端 SSLContext"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if getattr(opts, 'ssl_insecure', False):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    cafile = getattr(opts, 'ssl_ca', None)
    if cafile:
        ctx.load_verify_locations(cafile=cafile)
    else:
        ctx.load_default_certs()
    return ctx


def ssl_context_server(opts):
    """构建服务端 SSLContext"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certfile = getattr(opts, 'ssl_cert', None)
    keyfile = getattr(opts, 'ssl_key', None)
    if certfile:
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile or certfile)
    else:
        # 自动生成自签名证书 (仅开发测试)
        certfile, keyfile = generate_self_signed_cert()
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ctx


def generate_self_signed_cert():
    """用 openssl 或 cryptography 生成自签名证书, 失败则退化为内存警告"""
    import tempfile
    import subprocess as sp
    cert_path = os.path.join(tempfile.gettempdir(), 'nc_selfcert.pem')
    key_path = os.path.join(tempfile.gettempdir(), 'nc_selfkey.pem')
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    try:
        if os.name == 'nt':
            # Windows: 尝试系统是否装了 openssl
            sp.run(
                ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                 '-out', cert_path, '-keyout', key_path,
                 '-days', '365', '-subj', '/CN=localhost'],
                check=True, capture_output=True, timeout=15,
            )
        else:
            sp.run(
                ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                 '-out', cert_path, '-keyout', key_path,
                 '-days', '365', '-subj', '/CN=localhost'],
                check=True, capture_output=True, timeout=15,
            )
        return cert_path, key_path
    except Exception:
        # 退化: 告诉用户必须手动提供证书
        raise RuntimeError(
            "SSL 服务端需要证书. 请用 --cert cert.pem --key key.pem 指定, "
            "或在系统中安装 openssl 并确保在 PATH 中."
        )


def ssl_wrap_client(sock, host, opts):
    """客户端: 包装 socket 为 SSL"""
    ctx = ssl_context_client(opts)
    # 即使跳过证书校验, 也保留 SNI (CDN/虚拟主机必需)
    return ctx.wrap_socket(sock, server_hostname=host)


def ssl_wrap_server(sock, opts):
    """服务端: 包装已 accept 的客户端 socket"""
    ctx = ssl_context_server(opts)
    return ctx.wrap_socket(sock, server_side=True)


# ============================================================
# SOCKS5 客户端 (经代理 CONNECT)
# ============================================================

def socks5_connect_via(proxy_host, proxy_port, target_host, target_port, opts):
    """通过 SOCKS5 代理建立到 target 的隧道"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    set_socket_options(sock, opts)
    sock.settimeout(opts.timeout)
    sock.connect((proxy_host, proxy_port))

    # 协商: VER=5, NMETHODS=2, 00=匿名, 02=账号密码
    proxy_user = getattr(opts, 'proxy_user', None)
    proxy_pass = getattr(opts, 'proxy_pass', None)
    methods = bytearray([0x00])
    if proxy_user is not None and proxy_pass is not None:
        methods.append(0x02)
    sock.sendall(bytes([SOCKS5_VERSION, len(methods)]) + bytes(methods))

    resp = recv_exact(sock, 2)
    if resp[0] != SOCKS5_VERSION:
        raise RuntimeError(f"SOCKS5 代理版本不匹配: {resp[0]}")
    method = resp[1]
    if method == 0xFF:
        raise RuntimeError("SOCKS5 代理拒绝所有认证方式")
    if method == 0x02:
        # 账号密码认证 (RFC 1929)
        u = proxy_user.encode('utf-8')
        p = proxy_pass.encode('utf-8')
        auth_pkt = bytearray([0x01, len(u)]) + u + bytes([len(p)]) + p
        sock.sendall(bytes(auth_pkt))
        ar = recv_exact(sock, 2)
        if ar[1] != 0x00:
            raise RuntimeError("SOCKS5 代理认证失败")
    elif method != 0x00:
        raise RuntimeError(f"不支持的 SOCKS5 认证方法: {method}")

    # CONNECT 请求
    host_b, atype = encode_socks5_addr(target_host)
    port_b = struct.pack('!H', target_port)
    req = bytes([SOCKS5_VERSION, 0x01, 0x00, atype]) + host_b + port_b
    sock.sendall(req)

    resp = recv_exact(sock, 4)
    if resp[1] != 0x00:
        errs = {1: 'general SOCKS server failure',
                2: 'connection not allowed',
                3: 'network unreachable',
                4: 'host unreachable',
                5: 'connection refused',
                6: 'TTL expired',
                7: 'command not supported',
                8: 'address type not supported'}
        raise RuntimeError(f"SOCKS5 代理错误: {errs.get(resp[1], f'code={resp[1]}')}")
    # 读取 BND.ADDR + BND.PORT (忽略)
    if resp[3] == 0x01:
        recv_exact(sock, 4)
    elif resp[3] == 0x03:
        l = recv_exact(sock, 1)[0]
        recv_exact(sock, l)
    elif resp[3] == 0x04:
        recv_exact(sock, 16)
    recv_exact(sock, 2)
    return sock


def encode_socks5_addr(host):
    """把 host 编码成 SOCKS5 ATYP + ADDR"""
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            return ip.packed, 0x01
        else:
            return ip.packed, 0x04
    except ValueError:
        b = host.encode('idna') if any(ord(c) > 127 for c in host) else host.encode('ascii')
        return bytes([len(b)]) + b, 0x03


def decode_socks5_addr(sock, atype):
    """从 socket 读取 SOCKS5 地址字段, 返回 (host, port 留给外层读)"""
    if atype == 0x01:
        data = recv_exact(sock, 4)
        return '.'.join(str(b) for b in data)
    elif atype == 0x03:
        l = recv_exact(sock, 1)[0]
        return recv_exact(sock, l).decode('idna')
    elif atype == 0x04:
        data = recv_exact(sock, 16)
        return str(ipaddress.IPv6Address(data))
    raise RuntimeError(f"不支持的 SOCKS5 地址类型: {atype}")


def recv_exact(sock, n):
    """精确接收 n 字节"""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("连接已关闭")
        buf.extend(chunk)
    return bytes(buf)


# ============================================================
# SOCKS5 服务端 (本工具作为代理)
# ============================================================

def socks5_server(listen_host, listen_port, opts):
    """SOCKS5 代理服务端"""
    server = server_listen(listen_host, listen_port, opts)
    eprint(f"[socks5] listening on {listen_host}:{listen_port}")

    def handle(client):
        try:
            client.settimeout(opts.timeout)
            # 协商
            hdr = recv_exact(client, 2)
            if hdr[0] != SOCKS5_VERSION:
                client.close()
                return
            nm = hdr[1]
            methods = recv_exact(client, nm)
            # 只支持无认证 (0x00)
            if 0x00 in methods:
                client.sendall(bytes([SOCKS5_VERSION, 0x00]))
            else:
                client.sendall(bytes([SOCKS5_VERSION, 0xFF]))
                client.close()
                return

            # 请求
            req = recv_exact(client, 4)
            if req[0] != SOCKS5_VERSION or req[1] != 0x01:  # CONNECT only
                client.sendall(bytes([SOCKS5_VERSION, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
                client.close()
                return
            atype = req[3]
            host = decode_socks5_addr(client, atype)
            port = struct.unpack('!H', recv_exact(client, 2))[0]

            if opts.verbose:
                eprint(f"[socks5] CONNECT {host}:{port}")

            # 连接目标
            try:
                remote = client_connect(host, port, opts)
            except Exception as e:
                eprint(f"[socks5] target unreachable: {e}")
                client.sendall(bytes([SOCKS5_VERSION, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
                client.close()
                return

            # 响应 BND.ADDR + BND.PORT
            local_addr = remote.getsockname()
            if ':' in local_addr[0]:
                resp = bytes([SOCKS5_VERSION, 0x00, 0x00, 0x01]) + socket.inet_aton('127.0.0.1') + struct.pack('!H', local_addr[1])
            else:
                resp = bytes([SOCKS5_VERSION, 0x00, 0x00, 0x01]) + socket.inet_aton(local_addr[0]) + struct.pack('!H', local_addr[1])
            client.sendall(resp)

            # 双向转发
            def pump(src, dst):
                try:
                    while True:
                        data = src.recv(opts.buffer_size)
                        if not data:
                            break
                        dst.sendall(data)
                except Exception:
                    pass
                finally:
                    try: src.shutdown(socket.SHUT_RD)
                    except Exception: pass
                    try: dst.shutdown(socket.SHUT_WR)
                    except Exception: pass

            t1 = threading.Thread(target=pump, args=(client, remote), daemon=True)
            t2 = threading.Thread(target=pump, args=(remote, client), daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()
        except Exception as e:
            if opts.verbose:
                eprint(f"[socks5] handler error: {e}")
        finally:
            try: client.close()
            except Exception: pass

    try:
        while True:
            client, addr = server.accept()
            if opts.verbose:
                eprint(f"[socks5] connection from {addr}")
            threading.Thread(target=handle, args=(client,), daemon=True).start()
    except KeyboardInterrupt:
        eprint("\n[socks5] stopped")
    finally:
        try: server.close()
        except Exception: pass


# ============================================================
# 客户端 (发起连接)
# ============================================================

def client_connect(host, port, opts):
    """主动连接到 host:port (支持 SOCKS5 代理)"""
    # 代理模式优先
    proxy = getattr(opts, 'proxy', None)
    if proxy:
        phost, pport = proxy
        sock = socks5_connect_via(phost, pport, host, port, opts)
    else:
        fam = socket_family_from_host(host, getattr(opts, 'ipv6', False))
        sock_type = socket_type_from_mode(getattr(opts, 'mode', 'tcp'))

        sock = None
        if fam is not None:
            sock = socket.socket(fam, sock_type)
        else:
            infos = socket.getaddrinfo(host, port, 0, sock_type)
            last_err = None
            for fam, st, proto, canon, sockaddr in infos:
                try:
                    sock = socket.socket(fam, st, proto)
                    break
                except OSError as e:
                    last_err = e
            if sock is None:
                raise last_err

        set_socket_options(sock, opts)
        sock.settimeout(opts.timeout)

        try:
            sock.connect((host, port))
        except Exception:
            sock.close()
            raise

    # SSL 包装 (TCP + 启用 SSL)
    if getattr(opts, 'ssl', False) and getattr(opts, 'mode', 'tcp') == 'tcp':
        sock = ssl_wrap_client(sock, host, opts)

    return sock


# ============================================================
# 服务器 (监听)
# ============================================================

def server_listen(host, port, opts):
    """绑定并监听"""
    fam = socket_family_from_host(host or '0.0.0.0', getattr(opts, 'ipv6', False))
    sock_type = socket_type_from_mode(getattr(opts, 'mode', 'tcp'))

    bind_host = host
    if bind_host is None:
        bind_host = '::' if fam == socket.AF_INET6 else '0.0.0.0'

    sock = socket.socket(fam, sock_type)
    set_socket_options(sock, opts)

    if fam == socket.AF_INET6:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass

    try:
        sock.bind((bind_host, port))
    except OSError:
        sock.close()
        raise

    if getattr(opts, 'mode', 'tcp') == 'tcp':
        sock.listen(getattr(opts, 'backlog', 5))

    return sock


# ============================================================
# 数据交换 - 管道
# ============================================================

def relay(sock, opts, remote_addr=None):
    """双向数据转发"""
    stop_event = threading.Event()
    bytes_sent = [0]
    bytes_recv = [0]

    def recv_loop():
        try:
            while not stop_event.is_set():
                try:
                    data = sock.recv(opts.buffer_size)
                except socket.timeout:
                    if opts.keep_open:
                        continue
                    break
                except OSError as e:
                    if e.errno in (errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN):
                        break
                    raise
                if not data:
                    break
                bytes_recv[0] += len(data)
                try:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except BrokenPipeError:
                    break
        finally:
            stop_event.set()

    recv_thread = threading.Thread(target=recv_loop, daemon=True)
    recv_thread.start()

    try:
        while not stop_event.is_set():
            try:
                data = sys.stdin.buffer.read(opts.buffer_size)
            except KeyboardInterrupt:
                break
            if not data:
                break
            try:
                sock.sendall(data)
                bytes_sent[0] += len(data)
            except (BrokenPipeError, ConnectionResetError):
                break
    finally:
        stop_event.set()
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    recv_thread.join(timeout=2)
    try:
        sock.close()
    except OSError:
        pass

    if opts.verbose:
        eprint(f"[relay] sent={bytes_sent[0]}B recv={bytes_recv[0]}B")


# ============================================================
# 命令执行
# ============================================================

def run_command(cmd_or_shell, sock, opts):
    """在本地执行命令, 把 socket 当作 stdin/stdout/stderr"""
    is_shell = (cmd_or_shell is None)

    def reader():
        try:
            while True:
                data = sock.recv(opts.buffer_size)
                if not data:
                    break
                try:
                    stdin_pipe[1].write(data)
                    stdin_pipe[1].flush()
                except BrokenPipeError:
                    break
        except OSError:
            pass
        finally:
            try: stdin_pipe[1].close()
            except Exception: pass

    def writer(out_fh):
        try:
            while True:
                data = out_fh.read(opts.buffer_size)
                if not data:
                    break
                try: sock.sendall(data)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    break
        except Exception:
            pass
        finally:
            try: out_fh.close()
            except Exception: pass

    try:
        if is_shell:
            if os.name == 'nt':
                shell_exe = os.environ.get('COMSPEC', 'cmd.exe')
            else:
                shell_exe = os.environ.get('SHELL', '/bin/sh')
            cmd = [shell_exe]
        else:
            if os.name == 'nt':
                cmd = cmd_or_shell
            else:
                cmd = cmd_or_shell if isinstance(cmd_or_shell, list) else ['/bin/sh', '-c', cmd_or_shell]

        import io
        stdin_pipe_r, stdin_pipe_w = os.pipe()
        stdout_pipe_r, stdout_pipe_w = os.pipe()
        stderr_pipe_r, stderr_pipe_w = os.pipe()

        proc = subprocess.Popen(
            cmd,
            stdin=stdin_pipe_r,
            stdout=stdout_pipe_w,
            stderr=stderr_pipe_w,
            shell=(os.name == 'nt' and is_shell),
        )

        os.close(stdin_pipe_r)
        os.close(stdout_pipe_w)
        os.close(stderr_pipe_w)

        t_reader = threading.Thread(target=reader, daemon=True)
        t_stdout = threading.Thread(target=writer, args=(os.fdopen(stdout_pipe_r, 'rb'),), daemon=True)
        t_stderr = threading.Thread(target=writer, args=(os.fdopen(stderr_pipe_r, 'rb'),), daemon=True)
        t_reader.start(); t_stdout.start(); t_stderr.start()

        proc.wait()
        try: sock.shutdown(socket.SHUT_WR)
        except OSError: pass

        t_reader.join(timeout=3); t_stdout.join(timeout=3); t_stderr.join(timeout=3)
    except Exception as e:
        eprint(f"[exec] error: {e}")
    finally:
        try: sock.close()
        except OSError: pass


# ============================================================
# 文件传输
# ============================================================

def send_file(sock, filepath, opts):
    try:
        fh = sys.stdin.buffer if filepath == '-' else open(filepath, 'rb')
    except OSError as e:
        eprint(f"无法打开文件 {filepath}: {e}"); return

    total = 0
    try:
        while True:
            data = fh.read(opts.buffer_size)
            if not data: break
            sock.sendall(data)
            total += len(data)
            if opts.verbose and total % (opts.buffer_size * 80) < opts.buffer_size:
                eprint(f"[send] {total}B sent...")
    finally:
        if filepath != '-': fh.close()
        if opts.verbose: eprint(f"[send] done: {total}B")


def recv_file(sock, filepath, opts):
    try:
        fh = sys.stdout.buffer if filepath == '-' else open(filepath, 'wb')
    except OSError as e:
        eprint(f"无法创建文件 {filepath}: {e}"); return

    total = 0
    try:
        while True:
            try:
                data = sock.recv(opts.buffer_size)
            except socket.timeout:
                if opts.keep_open: continue
                break
            except OSError as e:
                if e.errno in (errno.ECONNRESET, errno.ENOTCONN): break
                raise
            if not data: break
            fh.write(data); fh.flush()
            total += len(data)
            if opts.verbose and total % (opts.buffer_size * 80) < opts.buffer_size:
                eprint(f"[recv] {total}B received...")
    finally:
        if filepath != '-': fh.close()
        else:
            try: fh.flush()
            except Exception: pass
        if opts.verbose: eprint(f"[recv] done: {total}B")


# ============================================================
# 端口扫描
# ============================================================

def scan_port(host, port, timeout=0.5, mode='tcp'):
    fam = socket_family_from_host(host)
    st = socket.SOCK_DGRAM if mode == 'udp' else socket.SOCK_STREAM
    if fam is None:
        fam = socket.AF_INET if ':' not in host else socket.AF_INET6

    s = socket.socket(fam, st)
    s.settimeout(timeout)
    try:
        if mode == 'tcp':
            s.connect((host, port))
        else:
            s.connect((host, port))
            s.sendall(b'\x00')
            try: s.recv(64)
            except socket.timeout: pass
        return True
    except Exception:
        return False
    finally:
        s.close()


def do_scan(host, ports, opts):
    import concurrent.futures
    open_ports = []
    eprint(f"Scanning {host} ports {len(ports)}...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=opts.threads) as pool:
        future_map = {pool.submit(scan_port, host, p, opts.timeout, opts.mode): p for p in ports}
        done = 0; total = len(ports)
        for fut in concurrent.futures.as_completed(future_map):
            p = future_map[fut]; done += 1
            if done % 50 == 0 or done == total:
                eprint(f"[{done}/{total}] scanning...", end='\r')
            try:
                if fut.result():
                    open_ports.append(p)
                    service = guess_service(p, opts.mode)
                    ssl_tag = '+ssl' if opts.ssl and opts.mode == 'tcp' else ''
                    print(f"port {p}/{opts.mode}{ssl_tag} open  {service}")
            except Exception: pass

    eprint()
    eprint(f"Done. Open ports: {len(open_ports)} ({open_ports})")


def guess_service(port, proto='tcp'):
    well = {
        (21, 'tcp'): 'ftp', (22, 'tcp'): 'ssh', (23, 'tcp'): 'telnet',
        (25, 'tcp'): 'smtp', (53, 'tcp'): 'dns', (80, 'tcp'): 'http',
        (110, 'tcp'): 'pop3', (143, 'tcp'): 'imap', (443, 'tcp'): 'https',
        (993, 'tcp'): 'imaps', (995, 'tcp'): 'pop3s', (3306, 'tcp'): 'mysql',
        (3389, 'tcp'): 'rdp', (5432, 'tcp'): 'postgres', (6379, 'tcp'): 'redis',
        (8080, 'tcp'): 'http-alt', (8443, 'tcp'): 'https-alt',
        (1080, 'tcp'): 'socks5',
    }
    return well.get((port, proto), '')


# ============================================================
# 端口转发
# ============================================================

def forward(source_host, source_port, target_host, target_port, opts):
    def handle_client(client_sock):
        try:
            remote = client_connect(target_host, target_port, opts)
        except Exception as e:
            eprint(f"[forward] cannot connect to {target_host}:{target_port}: {e}")
            try: client_sock.close()
            except OSError: pass
            return

        def pump(src, dst):
            try:
                while True:
                    data = src.recv(opts.buffer_size)
                    if not data: break
                    dst.sendall(data)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                try: src.shutdown(socket.SHUT_RD)
                except OSError: pass
                try: dst.shutdown(socket.SHUT_WR)
                except OSError: pass

        t1 = threading.Thread(target=pump, args=(client_sock, remote), daemon=True)
        t2 = threading.Thread(target=pump, args=(remote, client_sock), daemon=True)
        t1.start(); t2.start(); t1.join(); t2.join()
        try: client_sock.close()
        except OSError: pass
        try: remote.close()
        except OSError: pass

    server = server_listen(source_host, source_port, opts)
    eprint(f"[forward] listening on {source_host}:{source_port} -> {target_host}:{target_port}")

    try:
        while True:
            client, addr = server.accept()
            if opts.verbose: eprint(f"[forward] connection from {addr}")
            threading.Thread(target=handle_client, args=(client,), daemon=True).start()
    except KeyboardInterrupt:
        eprint("\n[forward] stopped")
    finally:
        try: server.close()
        except OSError: pass


# ============================================================
# UDP 客户端
# ============================================================

def udp_send_recv(host, port, opts):
    sock = client_connect(host, port, opts)
    eprint(f"udp -> {host}:{port}")

    def recv_loop():
        try:
            while True:
                data, addr = sock.recvfrom(opts.buffer_size)
                if data:
                    sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
        except OSError: pass

    t = threading.Thread(target=recv_loop, daemon=True); t.start()
    try:
        while True:
            data = sys.stdin.buffer.read(opts.buffer_size)
            if not data: break
            sock.sendto(data, (host, port))
    except KeyboardInterrupt: pass
    finally: sock.close()


# ============================================================
# 主入口
# ============================================================

def build_parser():
    p = argparse.ArgumentParser(
        prog='nc',
        description='Netcat (Python) - TCP/UDP/SSL/SOCKS5 网络瑞士军刀',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
常用示例:
  # 客户端连接
  nc host 80                              # TCP 明文
  nc -6 ::1 22                            # IPv6
  nc -u host 53                           # UDP
  nc --ssl host 443                       # SSL/TLS

  # 客户端经 SOCKS5 代理
  nc -x 127.0.0.1:1080 target 443          # 走本地代理
  nc -x proxy:1080 --proxy-user u --proxy-pass p target 443

  # 监听服务器
  nc -l -p 8080                           # TCP 监听
  nc -l -p 8443 --ssl --cert cert.pem --key key.pem   # SSL 监听
  nc -l -p 8080 -e cmd                    # 监听并执行命令
  nc -l -p 4444 -c                        # 交互式 shell

  # SOCKS5 代理服务器 (其他程序 -x 连接本端口)
  nc --socks5 -p 1080

  # 文件传输
  nc host 9000 < file.zip
  nc -l -p 9000 > file.zip

  # 端口扫描
  nc -z -w 1 host 1-1024

  # 端口转发
  nc -L -p 8080 -T host:80
        """,
    )

    # 位置参数
    p.add_argument('host', nargs='?', default=None, help='目标主机')
    p.add_argument('port', nargs='?', default=None, help='目标端口')

    # 模式
    p.add_argument('-l', '--listen', action='store_true', help='监听模式')
    p.add_argument('-p', '--local-port', type=int, help='本地端口')
    p.add_argument('-s', '--source', help='绑定本地源地址')
    p.add_argument('-o', '--output', help='输出文件')
    p.add_argument('-i', '--input', help='输入文件')
    p.add_argument('--socks5', action='store_true', help='SOCKS5 代理服务器模式')

    # 协议
    p.add_argument('-u', '--udp', dest='mode', action='store_const', const='udp', default='tcp',
                   help='UDP 模式 (默认 TCP)')
    p.add_argument('-6', '--ipv6', action='store_true', help='强制 IPv6')

    # SSL/TLS
    p.add_argument('--ssl', action='store_true', help='启用 SSL/TLS (客户端或监听服务端)')
    p.add_argument('--ssl-insecure', action='store_true', help='跳过证书校验 (客户端)')
    p.add_argument('--ssl-cert', help='SSL 服务端证书文件 PEM')
    p.add_argument('--ssl-key', help='SSL 服务端私钥 PEM (默认与 cert 相同)')
    p.add_argument('--ssl-ca', help='SSL 客户端自定义 CA 证书')

    # SOCKS5
    p.add_argument('-x', '--proxy', help='SOCKS5 代理 host:port (客户端经代理连接)')
    p.add_argument('--proxy-user', help='SOCKS5 代理用户名')
    p.add_argument('--proxy-pass', help='SOCKS5 代理密码')

    # 命令执行
    p.add_argument('-e', '--exec', metavar='CMD', help='收到连接时执行命令')
    p.add_argument('-c', '--shell', action='store_true', help='交互式 shell')

    # 扫描 / 转发
    p.add_argument('-z', '--scan', action='store_true', help='仅端口探测')
    p.add_argument('-w', '--timeout', type=float, default=3.0, help='超时秒数 (默认 3.0)')
    p.add_argument('-L', '--forward-listen', action='store_true', help='转发监听模式')
    p.add_argument('-T', '--target', help='转发目标 host:port')

    # 杂项
    p.add_argument('-v', '--verbose', action='count', default=0, help='详细输出')
    p.add_argument('-k', '--keep-open', action='store_true', help='连接关闭后保持监听')
    p.add_argument('-n', '--no-dns', action='store_true', help='不做 DNS 解析')
    p.add_argument('-r', '--randomize', action='store_true', help='扫描时随机化端口')
    p.add_argument('-t', '--tcp-nodelay', action='store_true', help='TCP_NODELAY')
    p.add_argument('--backlog', type=int, default=5, help='TCP backlog')
    p.add_argument('--buffer-size', type=int, default=8192, help='读写缓冲')
    p.add_argument('--reuse', action='store_true', default=True, help='SO_REUSEADDR')
    p.add_argument('--no-reuse', dest='reuse', action='store_false', help='关闭 SO_REUSEADDR')
    p.add_argument('--ttl', type=int, help='IP TTL')
    p.add_argument('--send-buffer', type=int, help='SO_SNDBUF')
    p.add_argument('--recv-buffer', type=int, help='SO_RCVBUF')
    p.add_argument('--threads', type=int, default=50, help='扫描并发线程')
    p.add_argument('-V', '--version', action='version', version=f'nc v{VERSION}')

    return p


def parse_proxy(s):
    """解析 -x proxy:1080 -> (host, port)"""
    t = parse_host(s)
    if isinstance(t, tuple):
        return t
    raise ValueError(f"代理格式错误: {s}, 需要 host:port")


def main(argv=None):
    parser = build_parser()
    opts = parser.parse_args(argv)

    # --- 预处理 -x ---
    if opts.proxy:
        try:
            opts.proxy = parse_proxy(opts.proxy)
        except ValueError as e:
            parser.error(str(e))

    # --- SOCKS5 扫描也允许 SSL 标记 ---
    if opts.scan:
        if opts.host is None or opts.port is None:
            parser.error("扫描模式需要 host 和 port")
        ports = parse_ports(str(opts.port))
        if opts.randomize:
            import random; random.shuffle(ports)
        do_scan(opts.host, ports, opts)
        return 0

    # --- SOCKS5 代理服务器模式 ---
    if opts.socks5:
        port = opts.local_port or int(opts.port or 1080)
        host = opts.source or ('::' if opts.ipv6 else '0.0.0.0')
        socks5_server(host, port, opts)
        return 0

    # --- 转发模式 ---
    if opts.forward_listen:
        if opts.local_port is None:
            parser.error("-L 模式需要 -p")
        if not opts.target:
            parser.error("-L 模式需要 -T target:port")
        t = parse_host(opts.target)
        if not isinstance(t, tuple):
            parser.error("-T 应为 host:port 形式")
        lhost = opts.source or ('::' if opts.ipv6 else '0.0.0.0')
        forward(lhost, opts.local_port, t[0], t[1], opts)
        return 0

    # --- 监听模式 ---
    if opts.listen:
        port = opts.local_port or int(opts.port or 0)
        host = opts.source or ('::' if opts.ipv6 else '0.0.0.0')

        while True:
            try:
                server = server_listen(host, port, opts)
            except OSError as e:
                eprint(f"无法绑定 {host}:{port}: {e}")
                return 1

            if opts.verbose:
                tag = " SSL" if opts.ssl else ""
                eprint(f"[listen] {opts.mode.upper()}{tag} on {host}:{port}")

            if opts.mode == 'udp':
                try:
                    while True:
                        data, addr = server.recvfrom(opts.buffer_size)
                        if opts.verbose:
                            eprint(f"[udp] from {addr}, {len(data)}B")
                        if opts.exec or opts.shell:
                            import io
                            fake_stdin = io.BytesIO(data)
                            try: os.dup2(fake_stdin.fileno(), 0)
                            except Exception: pass
                            cmd = opts.exec if opts.exec else (os.environ.get('COMSPEC', 'cmd.exe') if os.name == 'nt' else os.environ.get('SHELL', '/bin/sh'))
                            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                            out, _ = proc.communicate(timeout=15)
                            try: server.sendto(out, addr)
                            except OSError: pass
                        elif opts.output:
                            with open(opts.output, 'ab') as fh: fh.write(data)
                        else:
                            sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
                except KeyboardInterrupt:
                    eprint("\n[udp] stopped"); break
                finally:
                    try: server.close()
                    except OSError: pass
                if not opts.keep_open: break
                continue

            # TCP 监听
            try:
                client, addr = server.accept()
            except KeyboardInterrupt:
                eprint("\n[listen] stopped")
                try: server.close()
                except OSError: pass
                return 0

            # 服务端 SSL 包装
            if opts.ssl:
                try:
                    client = ssl_wrap_server(client, opts)
                    if opts.verbose:
                        cipher = client.cipher()
                        eprint(f"[ssl] negotiated: {cipher[0]} {cipher[1]}")
                except ssl.SSLError as e:
                    eprint(f"[ssl] handshake failed: {e}")
                    try: client.close()
                    except OSError: pass
                    if not opts.keep_open: return 1
                    continue

            if opts.verbose:
                eprint(f"[accept] {addr}")

            try:
                if opts.exec: run_command(opts.exec, client, opts)
                elif opts.shell: run_command(None, client, opts)
                elif opts.output: recv_file(client, opts.output, opts)
                else: relay(client, opts, addr)
            finally:
                try: client.close()
                except OSError: pass
                try: server.close()
                except OSError: pass

            if not opts.keep_open: break
        return 0

    # --- 客户端模式 ---
    if opts.host is None or opts.port is None:
        parser.error("客户端需要 host 和 port, 或用 -l 监听")

    sock = client_connect(opts.host, int(opts.port), opts)
    if opts.verbose:
        tags = []
        if opts.mode == 'udp': tags.append('UDP')
        else: tags.append('TCP')
        if opts.ssl:
            tags.append('SSL/TLS')
            cipher = sock.cipher()
            eprint(f"[ssl] cipher: {cipher[0]} {cipher[1]}")
        if opts.proxy:
            tags.append(f"via SOCKS5 {opts.proxy[0]}:{opts.proxy[1]}")
        eprint(f"[connect] {'/'.join(tags)} -> {opts.host}:{opts.port}")

    if opts.input: send_file(sock, opts.input, opts)
    elif opts.mode == 'udp': udp_send_recv(opts.host, int(opts.port), opts)
    else: relay(sock, opts)

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        eprint("\n(interrupted)")
        sys.exit(130)
    except Exception as e:
        eprint(f"error: {e}")
        sys.exit(1)
