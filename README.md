A fast, async network utility tool written in Rust for DNS resolution, connectivity testing, and HTTP operations.

## Features

- **DNS Operations**
  - Forward DNS resolution (domain → IP addresses)
  - Reverse DNS lookup (IP → domain names)
  - Batch processing support

- **Connectivity Testing**
  - TCP-based ping (no root privileges required)
  - Configurable ping count
  - Statistics with success rate and average response time

- **HTTP Operations**
  - Async HTTP GET requests
  - Configurable timeout
  - Response status, size, and timing information

- **Performance**
  - Fully asynchronous operations using Tokio
  - Concurrent processing of multiple targets
  - Efficient batch operations

## Installation

### Prerequisites

- Rust 1.70 or higher
- Cargo

### Build from Source

```bash
git clone https://github.com/yourusername/netool.git
cd netool
cargo build --release
```

The compiled binary will be available at `target/release/netool`

### Install Globally

```bash
cargo install --path .
```

## Usage

### DNS Resolution

**Resolve a single domain:**
```bash
cargo run -- dns -o resolve -t google.com
```

**Resolve multiple domains from a file:**
```bash
cargo run -- dns -o resolve -t domains.txt
```

**Reverse DNS lookup:**
```bash
cargo run -- dns -o reverse -t 8.8.8.8
```

### Ping / Connectivity Test

**Ping a single IP:**
```bash
cargo run -- ping -t 8.8.8.8 -c 4
```

**Ping multiple IPs from a file:**
```bash
cargo run -- ping -t ips.txt -c 3
```

### HTTP GET Requests

**Single URL:**
```bash
cargo run -- get -t https://example.com
```

**Multiple URLs from a file:**
```bash
cargo run -- get -t urls.txt -o 15
```

**Custom timeout (in seconds):**
```bash
cargo run -- get -t https://example.com -o 30
```

## Command Reference

### DNS Command
```
cargo run -- dns [OPTIONS]

Options:
  -o, --operation <OPERATION>  Operation to perform [possible values: resolve, reverse]
  -t, --target <TARGET>        Target: single IP/domain or path to file
  -h, --help                   Print help
```

### Ping Command
```
cargo run -- ping [OPTIONS]

Options:
  -t, --target <TARGET>  Target: single IP or path to file
  -c, --count <COUNT>    Number of ping attempts [default: 4]
  -h, --help             Print help
```

### Get Command
```
cargo run -- get [OPTIONS]

Options:
  -t, --target <TARGET>      Target: single URL or path to file
  -o, --timeout <TIMEOUT>    Request timeout in seconds [default: 10]
  -h, --help                 Print help
```

## Input File Format

Create text files with one target per line. Lines starting with `#` are treated as comments.

**domains.txt:**
```
# List of domains to resolve
google.com
github.com
rust-lang.org
```

**ips.txt:**
```
# Public DNS servers
8.8.8.8
1.1.1.1
208.67.222.222
```

**urls.txt:**
```
# Websites to check
https://google.com
https://github.com
http://example.com
```

## Examples

### Check if multiple servers are responding
```bash
echo -e "8.8.8.8\n1.1.1.1\n208.67.222.222" > dns-servers.txt
cargo run -- ping -t dns-servers.txt -c 2
```

### Resolve all domains in a list
```bash
cargo run -- dns -o resolve -t domains.txt
```

### Check HTTP status of multiple websites
```bash
cargo run -- get -t urls.txt -o 5
```

### Reverse lookup for multiple IPs
```bash
echo -e "8.8.8.8\n1.1.1.1" > ips.txt
cargo run -- dns -o reverse -t ips.txt
```

## Output Examples

**DNS Resolution:**
```
[+] google.com -> [142.250.185.46, 2607:f8b0:4004:c07::71]
[+] github.com -> [140.82.113.4]
```

**Ping:**
```
[+] 8.8.8.8 -> Reply #1: time=15.2ms
[+] 8.8.8.8 -> Reply #2: time=14.8ms
[+] 8.8.8.8 -> Reply #3: time=15.1ms

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 received, 0.0% packet loss
Average time: 15.0ms
```

**HTTP GET:**
```
[+] https://example.com -> Status: 200 OK, Size: 1256 bytes, Time: 245ms
[+] https://github.com -> Status: 200 OK, Size: 245821 bytes, Time: 312ms
```

## Technical Details

### Dependencies

- **clap** - Command-line argument parsing
- **tokio** - Async runtime
- **trust-dns-resolver** - DNS resolution
- **reqwest** - HTTP client (with rustls-tls for pure Rust TLS)

### Why Rustls?

This project uses `rustls` instead of OpenSSL for TLS operations because:
- No system OpenSSL library dependencies required
- Pure Rust implementation (memory-safe)
- Easier cross-compilation
- No version conflicts with system libraries

### Ping Implementation Note

The ping functionality uses TCP connection attempts (port 80) rather than ICMP packets. This approach:
- Doesn't require root/administrator privileges
- Works in restricted network environments
- Provides a good indicator of host reachability

For true ICMP ping, consider using dedicated tools like `ping` or libraries that support raw sockets with elevated privileges.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### TODO / Future Enhancements

- [ ] Add support for ICMP ping with raw sockets
- [ ] Add traceroute functionality
- [ ] Support for custom HTTP headers
- [ ] JSON output format option
- [ ] Progress bars for batch operations
- [ ] Colorized output
- [ ] Export results to CSV/JSON
- [ ] IPv6 specific operations
- [ ] Port scanning functionality
- [ ] Certificate information for HTTPS

## License

MIT License - feel free to use this tool for any purpose.

## Acknowledgments

Built with Rust 🦀 and powered by the amazing Rust async ecosystem.

---

**Note:** This tool is intended for legitimate network diagnostics and testing purposes only. Always ensure you have permission to test network resources.
