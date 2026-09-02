# tomcat-ip-filter

`tomcat-ip-filter` is a simple, lightweight library providing IP address and CIDR block filtering for Apache Tomcat. It supports both **Layer 4 (Transport/Socket Level)** and **Layer 7 (Application/Valve Level)** filtering, allowing you to secure your Tomcat deployments regardless of your network topology and load balancer configuration.

Both components share the same robust backend (`IpFilterSupport`), supporting:
- Individual IP addresses (IPv4 and IPv6)
- CIDR blocks (e.g., `192.168.1.0/24`, `2001:db8::/32`)
- Comment lines starting with `#` and inline comments / extra whitespace stripping
- **Automatic hot-reloading**: Configuration files are monitored and reloaded dynamically without requiring a Tomcat restart.
- **Allow list / Block list support**: If an allow list is configured, matching IPs bypass the block list check. Non-allowed IPs are checked against the block list and rejected if matched.

---

## Build

```bash
./gradlew build      # or gradlew.bat build on Windows
```

The Gradle wrapper is included, so you don't need Gradle installed locally — the first run will download Gradle automatically.

This produces `build/libs/tomcat-ip-filter-1.0.0.jar`.

> **Note:** Before building, check `build.gradle` and set `tomcatVersion` to match the Tomcat version you're deploying to. Tomcat classes are `compileOnly` dependencies and are not bundled into the jar.

## Install

Copy the built jar into Tomcat's shared library classpath (`$CATALINA_HOME/lib/`):

```bash
cp build/libs/tomcat-ip-filter-1.0.0.jar $CATALINA_HOME/lib/
```

Or run the Gradle task if configured:
```bash
./gradlew installToTomcat
```

---

## Choosing Your Filtering Approach

Depending on your network architecture, choose the appropriate filter:

| Feature | Layer 4 (`FilteringNioEndpoint`) | Layer 7 (`FilteringValve`) |
| :--- | :--- | :--- |
| **Where it intercepts** | TCP socket accept (`accept()` time) | Catalina request pipeline (`Valve`) |
| **TLS / HTTP Overhead** | None (rejected before handshake/parsing) | Processes request up to Valve execution |
| **Source IP Source** | Direct TCP remote socket address | `request.getRemoteAddr()` (compatible with `RemoteIpValve`, etc.) |
| **Best Used For** | Direct-to-edge deployments or Layer 4 Load Balancers (TCP passthrough) | Layer 7 Reverse Proxies, API Gateways, and ALBs (terminating TLS/HTTP) |

---

## Configuration

### Option A: Layer 4 Filtering (`FilteringNioEndpoint`)

Use this when Tomcat receives direct TCP connections from clients or via a Layer 4 network load balancer that preserves the client's source IP.

Edit `$CATALINA_HOME/conf/server.xml` and configure your Connector to use `org.fakebelieve.tomcat.FilteringHttp11NioProtocol` (see `conf/connector-snippet.xml`):

```xml
<Connector port="8080"
           protocol="org.fakebelieve.tomcat.FilteringHttp11NioProtocol"
           blockedIpsFile="conf/blocked-ips.txt"
           allowedIpsFile="conf/allowed-ips.txt"
           connectionTimeout="20000"
           redirectPort="8443" />
```

### Option B: Layer 7 Filtering (`FilteringValve`)

Use this when Tomcat is behind a Layer 7 reverse proxy, API gateway, or load balancer (such as Nginx, HAProxy, or AWS ALB) that terminates TLS/HTTP and forwards traffic.

Combine this with Tomcat's standard `RemoteIpValve` so that `request.getRemoteAddr()` correctly reflects the original client IP forwarded via proxy headers (e.g., `X-Forwarded-For`).

Add the `FilteringValve` to your `<Host>`, `<Context>`, or `<Engine>` block in `$CATALINA_HOME/conf/server.xml`:

```xml
<Host name="localhost"  appBase="webapps" unpackWARs="true" autoDeploy="true">

    <!-- Optional: Restores client IP from proxy headers if applicable -->
    <Valve className="org.apache.catalina.valves.RemoteIpValve" />

    <!-- IP Filtering Valve -->
    <Valve className="org.fakebelieve.tomcat.FilteringValve"
           blockedIpsFile="conf/blocked-ips.txt"
           allowedIpsFile="conf/allowed-ips.txt"
           errorCode="444" />
</Host>
```

#### Supported `FilteringValve` Attributes:
- **`className`**: Must be set to `org.fakebelieve.tomcat.FilteringValve`.
- **`blockedIpsFile`**: Path to the file containing blocked IP addresses or CIDR blocks (one per line). Automatically monitored and hot-reloaded.
- **`allowedIpsFile`** (or `allowedIpFile`): Path to the allowed IPs file. Connections matching these bypass the block list.
- **`errorCode`**: HTTP status code to return when rejecting a request (defaults to `403` Forbidden; e.g., `444` or `404`).

---

## Fail2ban Integration

Both `FilteringNioEndpoint` and `FilteringValve` monitor their respective filter files dynamically. You can integrate `tomcat-ip-filter` with [Fail2ban](https://github.com/fail2ban/fail2ban) to automatically ban or unban malicious IP addresses at runtime without restarting Tomcat.

Below is an example Fail2ban action configuration (typically placed in `/etc/fail2ban/action.d/tomcat-block.conf`):

```ini
[Definition]

# Executed when an IP is banned
actionban = if ! grep -q "^<ip> " /usr/local/tomcat/conf/blocked-ips.txt 2>/dev/null; then \
                echo "<ip> BLOCKED" >> /usr/local/tomcat/conf/blocked-ips.txt; \
            fi

# Executed when an IP is unbanned
actionunban = sed -i '/^<ip> /d' /usr/local/tomcat/conf/blocked-ips.txt

# Executed when Fail2ban starts/reloads
actionstart = touch /usr/local/tomcat/conf/blocked-ips.txt && \
              chown app:app /usr/local/tomcat/conf/blocked-ips.txt 2>/dev/null || true

# Executed when Fail2ban stops
actionstop =
```

---

## Notes & Compatibility

- **Tomcat Version**: This library is designed for and works with **Tomcat 9**.
- **Connector Support**: `FilteringNioEndpoint` is tested against the NIO connector (`Http11NioProtocol` / `NioEndpoint`). If APR/native connector is enabled, socket-level filtering is bypassed unless explicitly using the NIO protocol class.
- **File Paths**: Relative paths for `blockedIpsFile` and `allowedIpsFile` are resolved relative to `$CATALINA_BASE`. Absolute paths are also fully supported.
