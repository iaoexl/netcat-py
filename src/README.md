# nc 使用手册

> Python 实现的网络瑞士军刀，**单文件 + 独立 EXE** 两种形态，零第三方依赖。
> 对标 [eternallybored.org/misc/netcat](https://eternallybored.org/misc/netcat/)，并扩展 **SSL/TLS 加密** 和 **SOCKS5 代理**。
> 纯 Python / PyInstaller 打包，主流杀软不报毒。

---

## ⚠️ 免责声明（Disclaimer）：

此工具纯属教育用途。
（This tool is created purely for educational purposes.）
请勿在非您所有或未经明确许可的系统上进行测试。
（Do not use it on systems you do not own or have explicit permission to test.）

---

## 目录

- [交付物](#交付物)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [命令格式](#命令格式)
- [模式详解](#模式详解)
  - [1. 客户端连接](#1-客户端连接)
  - [2. 监听服务器](#2-监听服务器)
  - [3. 文件传输](#3-文件传输)
  - [4. 命令执行 / Shell](#4-命令执行--shell)
  - [5. 端口扫描](#5-端口扫描)
  - [6. 端口转发](#6-端口转发)
  - [7. SSL/TLS 加密通信](#7-ssltls-加密通信)
  - [8. SOCKS5 代理](#8-socks5-代理)
- [完整参数表](#完整参数表)
- [高级用法](#高级用法)
- [常见问题 FAQ](#常见问题-faq)
- [退出码](#退出码)

---

## 交付物

| 文件 | 说明 | 适用场景 |
|---|---|---|
| `netcat.py` | Python 源码，单文件 | 开发调试、二次开发、需要跨平台源码 |
| `dist/nc.exe` | PyInstaller 打包的独立 EXE | **直接使用**，无需装 Python，拷走即用 |
| `nc.spec` | PyInstaller 打包配置 | 修改源码后重新打包用 |

推荐日常直接用 `nc.exe`。

---

## 环境要求

| 项目 | Python 源码 | nc.exe |
|---|---|---|
| 运行环境 | Python ≥ 3.7 | 无需 Python |
| 操作系统 | Windows / Linux / macOS | Windows 64 位 |
| 依赖 | **无**（仅标准库，含 `ssl`） | 无 |
| 权限 | 监听 < 1024 端口需 root | 监听 < 1024 端口需管理员 |

---

## 快速开始

### 如果用 nc.exe（推荐）

```powershell
# 加入 PATH (一次性)
$env:Path += ";d:\scripts\python\netcat\dist"

# 查看帮助 / 版本
nc --help
nc --version        # → nc v1.1.0

# 最简测试
# 终端 A
nc -l -p 8080
# 终端 B
echo "hello" | nc 127.0.0.1 8080
```

### 如果用 Python 源码

```powershell
python netcat.py --help
python netcat.py -l -p 8080
echo "hello" | python netcat.py 127.0.0.1 8080
```

> 下文示例统一用 `nc` 作为命令名，Python 用户把 `nc` 换成 `python netcat.py` 即可。

---

## 命令格式

```
nc [选项] <host> <port>                     # 客户端模式
nc -l [选项] -p <port>                      # 监听模式
nc -z [选项] <host> <ports>                 # 扫描模式
nc -L [选项] -p <port> -T <target>          # 转发模式
nc --socks5 -p <port>                       # SOCKS5 代理服务器模式
```

---

## 模式详解

### 1. 客户端连接

最基础的用法，主动 TCP 连接到目标。

```powershell
# TCP 明文连接
nc 192.168.1.100 80

# 连接 SSH
nc 127.0.0.1 22

# 强制 IPv6
nc -6 ::1 8080

# UDP 模式 (DNS 查询示例)
nc -u 8.8.8.8 53

# 绑定本地源地址 (多网卡)
nc -s 192.168.1.50 10.0.0.1 443

# 超时 2 秒
nc -w 2 host.com 443

# 低延迟交互 (TCP_NODELAY)
nc -t host 22
```

### 2. 监听服务器

被动等待连接，类似 `nc -l -p PORT`。

```powershell
# 监听任意网卡 8080
nc -l -p 8080

# 只监听指定地址
nc -l -p 8080 -s 192.168.1.50

# IPv6 监听
nc -l -p 8080 -6

# UDP 监听
nc -l -u -p 5060

# 保持监听 (客户端断开后继续等)
nc -l -p 8080 -k

# 详细日志
nc -l -p 8080 -v
```

### 3. 文件传输

通过 stdin/stdout 或 `-i / -o` 参数传文件。

#### 发送文件

```powershell
# 方式一：stdin 重定向
nc target 9000 < payload.zip

# 方式二：-i 指定
nc target 9000 -i payload.zip

# 显示进度
nc target 9000 -i bigfile.iso -v
```

#### 接收文件

```powershell
# 方式一：stdout 重定向
nc -l -p 9000 > received.zip

# 方式二：-o 指定
nc -l -p 9000 -o received.zip
```

> ⚠️ TCP 是流式协议，发送端关闭后接收端才停止。传大文件建议用 `-v` 观察字节数对齐。

### 4. 命令执行 / Shell

**⚠️ 仅限合法授权的测试/运维场景，未授权使用违法！**

```powershell
# Windows: 收到连接执行 ipconfig
nc -l -p 4444 -e "ipconfig"

# Windows: 反弹 cmd
nc -l -p 4444 -c

# Linux: 执行指定命令
nc -l -p 4444 -e "ls -la /"

# Linux: 反弹 /bin/sh
nc -l -p 4444 -e "/bin/sh -i"

# 客户端侧连接过去交互
nc 10.0.0.5 4444

# 单次执行后等下一个连接
nc -l -p 4444 -e "whoami" -k
```

### 5. 端口扫描

快速探测目标开放端口，内置并发线程池。

```powershell
# 扫描单端口
nc -z -w 1 192.168.1.1 22

# 扫描范围
nc -z -w 1 192.168.1.1 1-1024

# 扫描列表
nc -z -w 0.5 host.com 22,80,443,3306,8080

# 全端口 + 详细
nc -z -w 1 -v target 1-65535

# 随机顺序 (绕简单 IDS)
nc -z -w 1 -r target 1-1024

# 并发调优
nc -z -w 1 --threads 100 target 1-10000

# UDP 扫描
nc -z -u -w 2 target 53,161
```

#### 输出示例

```
Scanning 192.168.1.1 ports 5...
port 22/tcp open  ssh
port 80/tcp open  http
port 443/tcp open  https
port 3306/tcp open  mysql
Done. Open ports: 4 ([22, 80, 443, 3306])
```

### 6. 端口转发

类似 `socat` / `nc -L`，把请求透明转发到上游。

```powershell
# 本地 8080 -> 外网 80
nc -L -p 8080 -T example.com:80

# 内网穿透：本地 13389 -> 目标 RDP
nc -L -p 13389 -T 10.0.0.5:3389

# 绑定指定网卡
nc -L -p 8080 -T 10.0.0.5:80 -s 192.168.1.50

# UDP 转发
nc -L -u -p 5060 -T 10.0.0.5:5060

# 带 SOCKS5 代理的转发 (本工具作为客户端走代理转发到目标)
nc -L -p 8080 -T example.com:443 -x 127.0.0.1:1080
```

#### 工作原理

```
客户端 ──▶ nc(监听端) ──▶ 真实目标
             │
             └── 双向 pump 线程
```

每个连接起两个 pump 线程（A→B / B→A），任一方关闭即清理。

### 7. SSL/TLS 加密通信

内置 TLS 1.2/1.3 支持，客户端和服务端双向都能用。

#### 客户端（连接 HTTPS / TLS 服务）

```powershell
# 最常用：跳过证书校验（开发/测试场景）
# Windows Python 默认 CA 库不全时推荐用这个
"HEAD / HTTP/1.1`r`nHost: example.com`r`nConnection: close`r`n`r`n" `
  | nc --ssl --ssl-insecure example.com 443 -v -w 5

# 输出示例：
# [ssl] cipher: TLS_AES_256_GCM_SHA384 TLSv1.3
# [connect] TCP/SSL/TLS -> example.com:443

# 生产环境：严格校验证书 (需 --ssl-ca 指定 CA, 或系统自带)
nc --ssl --ssl-ca C:\path\to\ca.pem secure.example.com 443

# 经 SOCKS5 代理 + SSL 连接 (双重加密链路)
nc -x 127.0.0.1:1080 --ssl --ssl-insecure target.com 443 -v
```

#### 服务端（自己起一个 TLS 监听）

```powershell
# 方式一：指定现成证书
nc -l -p 8443 --ssl --cert cert.pem --key key.pem -v

# 方式二：让 nc 自动生成自签名证书 (需要系统装 openssl 在 PATH 里)
nc -l -p 8443 --ssl -v
# Windows 上如果没 openssl, 请先用下面命令手动生成一次:
#   openssl req -x509 -newkey rsa:2048 -nodes -out cert.pem -keyout key.pem `
#       -days 365 -subj "/CN=localhost"
```

#### SSL 命令执行

```powershell
# SSL 加密的反弹 shell
nc -l -p 8443 --ssl --cert cert.pem --key key.pem -c

# 客户端用 SSL 连过去
nc --ssl --ssl-insecure server.com 8443 -v
```

#### SSL 参数说明

| 参数 | 说明 | 客户端/服务端 |
|---|---|---|
| `--ssl` | 启用 TLS | 双向 |
| `--ssl-insecure` | 跳过证书校验（客户端） | 客户端 |
| `--ssl-cert FILE` | PEM 格式证书文件 | 服务端 |
| `--ssl-key FILE` | PEM 格式私钥（默认与 cert 相同文件） | 服务端 |
| `--ssl-ca FILE` | 自定义 CA 证书（覆盖系统默认） | 客户端 |

### 8. SOCKS5 代理

两种用法：作为**客户端**走代理，或作为**服务端**提供代理。

#### 用法 A：客户端走 SOCKS5 代理

```powershell
# 最简：经本地 1080 代理连目标
nc -x 127.0.0.1:1080 target.com 80 -v

# 输出示例:
# [connect] TCP/via SOCKS5 127.0.0.1:1080 -> target.com:80

# 带账号密码认证
nc -x proxy.example.com:1080 --proxy-user alice --proxy-pass secret target 443

# 走代理 + SSL (双重加密)
nc -x 127.0.0.1:1080 --ssl --ssl-insecure target.com 443 -v

# 扫描也能走代理（绕出口防火墙）
nc -x 127.0.0.1:1080 -z -w 2 192.168.1.100 22,3389
```

#### 用法 B：本工具作为 SOCKS5 代理服务器

```powershell
# 启动 SOCKS5 代理 (默认监听 1080)
nc --socks5 -p 1080 -v
# [socks5] listening on 0.0.0.0:1080

# 其他程序就可以 -x 连过来了
# 支持 CONNECT 命令 (TCP 隧道), 无认证

# 绑定指定网卡
nc --socks5 -p 1080 -s 192.168.1.50

# 配合 SSL: 代理服务器本身包一层 TLS (企业级加密 SOCKS)
nc -l -p 1443 --ssl --cert cert.pem --key key.pem -v
# 或者直接 --socks5 模式下加 --ssl:
#   nc --socks5 -p 1080 --ssl --cert cert.pem --key key.pem
```

#### SOCKS5 参数说明

| 参数 | 说明 |
|---|---|
| `-x HOST:PORT`, `--proxy` | 客户端经 SOCKS5 代理连接目标 |
| `--proxy-user` | SOCKS5 代理认证用户名 |
| `--proxy-pass` | SOCKS5 代理认证密码 |
| `--socks5` | 本工具作为 SOCKS5 代理服务端 |

#### 协议支持

- 支持 SOCKS5 CONNECT（TCP 隧道）
- 支持 SOCKS5 账号密码认证（RFC 1929）
- 支持 ATYP：IPv4 (0x01)、域名 (0x03)、IPv6 (0x04)

---

## 完整参数表

### 位置参数

| 参数 | 说明 |
|---|---|
| `host` | 目标主机 IP/域名；监听模式下留空表示 0.0.0.0 / :: |
| `port` | 目标端口 (客户端) 或端口范围 (扫描, 如 `1-1024`) |

### 模式

| 参数 | 说明 |
|---|---|
| `-l`, `--listen` | 监听模式 |
| `-p`, `--local-port PORT` | 本地端口 |
| `-s`, `--source ADDR` | 绑定本地源地址 |
| `-o`, `--output FILE` | 输出文件 |
| `-i`, `--input FILE` | 输入文件 |
| `--socks5` | SOCKS5 代理服务端模式 |

### 协议

| 参数 | 说明 | 默认 |
|---|---|---|
| `-u`, `--udp` | UDP 模式 | TCP |
| `-6`, `--ipv6` | 强制 IPv6 | IPv4 |

### SSL/TLS

| 参数 | 说明 | 客户端/服务端 |
|---|---|---|
| `--ssl` | 启用 TLS | 双向 |
| `--ssl-insecure` | 跳过证书校验 | 客户端 |
| `--ssl-cert FILE` | 服务端证书 PEM | 服务端 |
| `--ssl-key FILE` | 服务端私钥 PEM | 服务端 |
| `--ssl-ca FILE` | 自定义 CA 证书 | 客户端 |

### SOCKS5

| 参数 | 说明 |
|---|---|
| `-x HOST:PORT`, `--proxy` | SOCKS5 代理地址 (客户端经代理连接) |
| `--proxy-user USER` | SOCKS5 代理认证用户名 |
| `--proxy-pass PASS` | SOCKS5 代理认证密码 |
| `--socks5` | 本工具作为 SOCKS5 代理服务端 |

### 命令执行

| 参数 | 说明 |
|---|---|
| `-e`, `--exec CMD` | 连接到来时执行 CMD |
| `-c`, `--shell` | 交互式 shell |

### 扫描 / 转发

| 参数 | 说明 |
|---|---|
| `-z`, `--scan` | 仅探测 |
| `-L`, `--forward-listen` | 转发监听模式 |
| `-T`, `--target HOST:PORT` | 转发目标 |
| `-w`, `--timeout N` | 超时秒数 (默认 3.0) |
| `-r`, `--randomize` | 扫描随机化端口顺序 |
| `--threads N` | 扫描并发线程 (默认 50) |

### 服务器

| 参数 | 说明 | 默认 |
|---|---|---|
| `-k`, `--keep-open` | 客户端断开后继续监听 | 关闭 |
| `--backlog N` | TCP backlog | 5 |

### 高级 Socket

| 参数 | 说明 | 默认 |
|---|---|---|
| `--buffer-size N` | 读写缓冲 (字节) | 8192 |
| `--reuse / --no-reuse` | SO_REUSEADDR | 默认开启 |
| `--ttl N` | IP TTL | 系统默认 |
| `--send-buffer N` | SO_SNDBUF | 系统默认 |
| `--recv-buffer N` | SO_RCVBUF | 系统默认 |

### 其他

| 参数 | 说明 |
|---|---|
| `-v`, `--verbose` | 详细输出 (-v / -vv) |
| `-t`, `--tcp-nodelay` | TCP_NODELAY |
| `-n`, `--no-dns` | 不做 DNS 解析 |
| `-V`, `--version` | 版本号 |
| `-h`, `--help` | 帮助 |

---

## 高级用法

### HTTP 请求快速测试（明文 80 端口）

```powershell
(
  "GET / HTTP/1.1"
  "Host: example.com"
  ""
) | nc example.com 80
```

### HTTPS 请求（内置 SSL）

```powershell
(
  "HEAD / HTTP/1.1"
  "Host: example.com"
  "Connection: close"
  ""
) | nc --ssl --ssl-insecure example.com 443 -v -w 5
# 输出 [ssl] cipher: TLS_AES_256_GCM_SHA384 TLSv1.3
```

### 链式：SOCKS5 + SSL 加密穿透

```powershell
# 场景: 公司内网必须走代理 + 目标只接受 TLS
nc -x proxy.company.com:1080 --ssl --ssl-insecure internal-api.com 8443 -v
```

### 多客户端转发

```powershell
# 每次新连接自动处理
nc -L -p 8080 -T 127.0.0.1:8000 -v
# [forward] connection from ...
```

### 二进制管道

```powershell
# PowerShell
Get-Content .\bigfile.zip -Encoding Byte | nc target 9000 -v

# Linux: 压缩后发送
gzip -c backup.sql | nc target 9000

# Linux: 接收 + 解压
nc -l -p 9000 | gunzip > backup.sql
```

---

## 常见问题 FAQ

### Q1: Windows 下报 `PSSecurityException`？

PowerShell 默认禁未签名脚本，但 **本工具已打包为 nc.exe**，直接运行 `nc.exe` 不受此限制。Python 源码请用 `python .\netcat.py` 运行。

### Q2: 监听 80 端口报 `Permission denied`？

- Windows：用**管理员身份**开 PowerShell
- Linux/macOS：`sudo nc -l -p 80`

### Q3: 文件传输大小不匹配？

检查三点：
1. 发送端 `-v` 看是否完整发送
2. 发送端是否正确关闭连接（脚本已处理）
3. 是否中间代理截断 → 换 UDP 或分块

### Q4: Windows Python SSL 报 `CERTIFICATE_VERIFY_FAILED`？

Windows 上 Python 默认 CA 库可能不全。开发/测试场景用：

```powershell
nc --ssl --ssl-insecure target 443
```

生产环境：
```powershell
nc --ssl --ssl-ca C:\path\to\ca-bundle.pem secure.target.com 443
```

### Q5: SSL 服务端怎么生成证书？

装 [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html)，然后：

```powershell
openssl req -x509 -newkey rsa:2048 -nodes -out cert.pem -keyout key.pem `
    -days 365 -subj "/CN=localhost"
nc -l -p 8443 --ssl --cert cert.pem --key key.pem
```

### Q6: SOCKS5 代理支持哪些命令？

目前只实现了 **CONNECT**（TCP 隧道），这是 99% 场景的需求。BIND / UDP ASSOCIATE 暂未支持。需要的话告诉我再加。

### Q7: 命令执行模式会不会被杀软拦截？

- `nc.exe` 打包形态 + `-e cmd` / `-c` 行为**可能触发 EDR 启发式规则**
- 纯源码 `python netcat.py -e cmd.exe` 通常不触发
- 合法场景建议告知运维、用白名单、或用 SSH/WinRM

### Q8: 如何重新打包 nc.exe？

源码改了以后：

```powershell
cd d:\scripts\python\netcat
python -m PyInstaller nc.spec --noconfirm
# 结果在 dist\nc.exe
```

### Q9: 扫描慢？

```powershell
nc -z -w 0.3 --threads 200 target 1-1024
```

调小超时 + 加大线程。

### Q10: 能把 nc.exe 加入 PATH 全局用吗？

可以，两种方式：
1. **临时**：`$env:Path += ";d:\scripts\python\netcat\dist"`（当前会话）
2. **永久**：系统属性 → 环境变量 → Path → 新增 `d:\scripts\python\netcat\dist`

之后任何 PowerShell / CMD 窗口里直接敲 `nc --help`。

---

## 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 正常退出 |
| `1` | 参数错误 / 运行时异常 |
| `130` | Ctrl+C 中断 |

---

## 版本历史

| 版本 | 日期 | 变更 |
|---|---|---|
| `1.1.0` | 2026-11-24 | 新增 **SSL/TLS 加密**（客户端+服务端）、**SOCKS5 客户端代理**、**SOCKS5 服务端**；命令名由 `netcat.py` 统一为 `nc`；发布 `dist/nc.exe` |
