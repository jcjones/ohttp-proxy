# OHTTP Proxy

A SOCKS5 proxy (RFC 1928) that routes traffic through Oblivious HTTP (RFC 9458) using Binary HTTP messages (RFC 9292).

This project is not intended for production use. It does not do any work to strip deanonymizing headers from the HTTP requests it forwards. It is built for experimenting with OHTTP and BHTTP.

## Overview

This proxy accepts standard SOCKS5 TCP connections and forwards HTTP requests through an OHTTP relay to provide an additional layer of privacy. The proxy encapsulates HTTP requests using OHTTP, sends them via a relay server, and decapsulates the responses before returning them to the client.

Technically, this project can send directly to an OHTTP gateway, though that compromises the point of OHTTP.

> [!NOTE]
> This project does not seek to implement a complete SOCKS5 proxy. Neither `UDP Associate` nor `BIND` are supported. Additionally, DNS in the SOCKS protocol is ignored and left to the Gateway to perform.

## Missing Features
- **Full IPv6 support**: It somewhat works, but it needs more baking and tests.
- **HTTP/2**: SOCKS5 doesn't support HTTP/2, so it'll always downgrade. Guess that needs a normal HTTP proxy, eh?
- **HTTP Proxy support**: SOCKS5 was simpler to get started with, but support for standard RFC 9110 HTTP proxies is desireable, to support HTTP/2.

## Installation

```bash
cargo build --release
```

## Usage

### Basic Usage

```bash
./target/release/ohttp-proxy \
  --ohttp-relay-url https://relay.example.com \
  --ohttp-configuration-url https://relay.example.com/ohttp-configs
```

### Advanced Usage with Authentication

```bash
./target/release/ohttp-proxy \
  --socks5 127.0.0.1:8080 \
  --ohttp-relay-url https://relay.example.com/gateway \
  --ohttp-configuration-url https://relay.example.com/ohttp-configs \
  --relay-headers "X-Auth-Token=your-secret-token" \
  --relay-headers "X-Client-ID=your-client-id" \
  --ca-cert /path/to/custom-ca.pem \
  --verbose
```

### Command Line Options

- `--socks5 <ADDRESS>`: Socket address to listen for SOCKS5 requests on (default: `[::]:32547`)

- `--ohttp-relay-url <URL>`: URL of the OHTTP relay server (required)

- `--ohttp-configuration-url <URL>`: URL to fetch OHTTP configuration from (required)

- `--relay-headers <HEADER>`: Custom HTTP headers to send to the relay (format: `Name=Value`)
  - Can be specified multiple times for multiple headers.

- `--ca-cert <PATH>`: Path to custom CA certificate file in PEM format

- `--verbose`: Increase log level, can be specified more tha once.
  - Once (`-v`) enables DEBUG, while `-vv` enables TRACE.

## Example Client Usage

Once the proxy is running, configure your application to use it as a SOCKS5 proxy:

### Using curl
```bash
curl --socks5 127.0.0.1:32547 http://httpbin.org/ip
```

### Using httpie
```bash
http --proxy=http:socks5://127.0.0.1:32547 http://ipinfo.io/ip
```

### Browser Configuration
You can configure your browser to use `127.0.0.1:32547` as a SOCKS5 proxy, but expect most things to break. This is not
a full SOCKS5 implementation.

## Architecture

1. **Client** → SOCKS5 connection → **OHTTP SOCKS5 Proxy**
2. **Proxy** encapsulates HTTP request with OHTTP
3. **Proxy** → HTTPS → **OHTTP Relay**
4. **Relay** → **Target Server**
5. Response flows back through the same path with OHTTP decapsulation

## Testing

Run the unit test suite:

```bash
cargo test
```

### Local Testing

To stand up a local OHTTP gateway (https://github.com/cloudflare/privacy-gateway-server-go) using Docker, see
the `./start_local_gateway.sh` script, then start this tool as follows:
```bash
cargo run -- --ohttp-relay-url https://localhost:4567/gateway \
  --ohttp-configuration-url https://localhost:4567/ohttp-configs \
  --verbose
```

Great thanks to @FiloSottile for https://github.com/FiloSottile/mkcert, also used in that script.

## License

This project is licensed under the MPL-2.0 License.

## References

- [RFC 9458: Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [RFC 9292: Binary Representation of HTTP Messages](https://www.rfc-editor.org/rfc/rfc9292.html)
- [RFC 1928: SOCKS Protocol Version 5](https://www.rfc-editor.org/rfc/rfc1928.html)