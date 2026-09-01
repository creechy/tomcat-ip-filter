# tomcat-ip-filter

A minimal Gradle project that builds a custom Tomcat NIO endpoint
(`FilteringNioEndpoint`) which rejects connections from blocked IPs/CIDRs (with an optional allow list to bypass block-list checks) at
`accept()` time — before TLS handshake or HTTP parsing.

## Build

```bash
./gradlew build      # or gradlew.bat build on Windows
```

The Gradle wrapper is included, so you don't need Gradle installed
locally — the first run will download Gradle 8.10.2 automatically.

This produces `build/libs/tomcat-ip-filter-1.0.0.jar`.

Before building, check `build.gradle` and set `tomcatVersion` to match
the Tomcat version you're deploying to (the Tomcat classes are only
`compileOnly` — they are not bundled into the jar).

## Install

Copy the jar into Tomcat's own classpath (not a webapp's `WEB-INF/lib`,
since this needs to load as part of connector bootstrap, before any
webapp does):

```bash
cp build/libs/tomcat-ip-filter-1.0.0.jar $CATALINA_HOME/lib/
```

or:

```bash
cp build/libs/tomcat-ip-filter-1.0.0.jar $CATALINA_HOME/lib/
```

or:

```bash
./gradlew installToTomcat   # uses $CATALINA_HOME/lib automatically
```

## Configure

Edit `$CATALINA_HOME/conf/server.xml` and point your connector at the
custom protocol class instead of the default `"HTTP/1.1"` alias — see
`conf/connector-snippet.xml` for the exact attribute. You can also specify a
`blockedIpsFile` and/or `allowedIpsFile` (or `allowedIpFile`) attribute to automatically load blocked or allowed IPs from files at startup:

```xml
<Connector port="8080"
           protocol="org.fakebelieve.tomcat.FilteringHttp11NioProtocol"
           blockedIpsFile="conf/blocked-ips.txt"
           allowedIpsFile="conf/allowed-ips.txt"
           connectionTimeout="20000"
           redirectPort="8443" />
```

The file can contain individual IP addresses (IPv4 or IPv6) or CIDR blocks (e.g., `192.168.1.0/24` or `2001:db8::/32`), one per line. Blank lines and comments starting with `#` are ignored (inline comments and extra whitespace are also stripped). 

If an allowed IPs file is configured, any connection from an IP present on the allow list or within an allowed CIDR block will be permitted immediately, bypassing the block list check. If an IP is not on the allow list, it is still checked against the block list and permitted unless explicitly blocked or matching a blocked CIDR block.

The IP/CIDR files are monitored for changes; if you modify the files while Tomcat is running, the changes will be automatically detected and reloaded without requiring a restart.

## Fail2ban Integration

You can integrate `tomcat-ip-filter` with [Fail2ban](https://github.com/fail2ban/fail2ban) to automatically block malicious IP addresses by updating your configured `blockedIpsFile` when Fail2ban bans or unbans an IP.

Because `tomcat-ip-filter` dynamically monitors the block list file for changes, any updates made by Fail2ban take effect immediately without requiring a Tomcat restart.

Below is an example custom Fail2ban action (typically placed in `/etc/fail2ban/action.d/tomcat-block.conf`) that manages the block list:

```ini
[Definition]

# Executed when an IP is banned
# Appends "IP_ADDRESS BLOCKED" to banned-ips.txt if not already present
actionban = if ! grep -q "^<ip> " /usr/local/tomcat/conf/banned-ips.txt 2>/dev/null; then \
                echo "<ip> BLOCKED" >> /usr/local/tomcat/conf/banned-ips.txt; \
            fi

# Executed when an IP is unbanned
# Removes any line starting with the IP address from banned-ips.txt
actionunban = sed -i '/^<ip> /d' /usr/local/tomcat/conf/banned-ips.txt

# Executed when Fail2ban starts/reloads
# Ensures the banned-ips.txt file exists and has correct permissions
actionstart = touch /usr/local/tomcat/conf/banned-ips.txt && \
              chown app:app /usr/local/tomcat/conf/banned-ips.txt 2>/dev/null || true

# Executed when Fail2ban stops
actionstop =
```

## Deployment Contexts and Load Balancers

This filter rejects connections at the socket level (`accept()` time) based on the direct remote IP address of the incoming TCP connection. Therefore, **it is only useful when Tomcat is deployed directly on the edge or behind a Layer 4 (Network) Load Balancer** that preserves the client's source IP address. 

If Tomcat is deployed behind a Layer 7 (Application) reverse proxy or load balancer (such as an Nginx reverse proxy, API gateway, or AWS ALB that terminates TLS/HTTP and forwards requests), Tomcat will only see the load balancer's or proxy's internal IP address, rendering IP-based filtering at this layer ineffective for the actual clients. 

### Layer 7 Alternative (Tomcat RewriteValve)

For Layer 7 deployments where you need to block clients based on headers like `X-Forwarded-For`, use Tomcat's built-in `RewriteValve` instead. 

#### Example: Using Tomcat's `RewriteValve` with an External Text File (`RewriteMap`)

Tomcat's `RewriteValve` supports a `RewriteMap` directive (similar to Apache mod_rewrite), allowing you to load an external text file for lookups (such as a blocked IP list):

1. Add the `RewriteValve` to your `<Host>` or `<Context>` in `$CATALINA_HOME/conf/server.xml`:
   ```xml
   <Host name="localhost"  appBase="webapps" unpackWARs="true" autoDeploy="true">
       <Valve className="org.apache.catalina.valves.rewrite.RewriteValve" />
   </Host>
   ```

2. Create your block list file (e.g., `$CATALINA_HOME/conf/blocked-ips.txt`) where each line maps an IP to a status value:
   ```text
   # /usr/local/tomcat/conf/blocked-ips.txt
   192.168.1.100 BLOCKED
   203.0.113.50 BLOCKED
   ```

3. Configure the `RewriteMap` and rule in your `rewrite.config` file (placed under `$CATALINA_HOME/conf/Catalina/localhost/rewrite.config` or `WEB-INF/rewrite.config`):
   ```text
   # Define a text-based map pointing to the block-list file
   RewriteMap blockedIPs txt:conf/blocked-ips.txt

   # Check if the X-Forwarded-For header exists in the blockedIPs map and return status 444
   RewriteCond ${blockedIPs:%{HTTP:X-Forwarded-For}} !=""
   RewriteRule ^.*$ - [R=444]
   ```
   *(Note: This allows you to maintain an external text file for Layer 7 requests similar to how socket-level filtering uses files).*

## Notes

- Only tested against the NIO connector (`Http11NioProtocol` /
  `NioEndpoint`). If APR/native is enabled on your server, this won't
  be used unless you also point the connector explicitly at the NIO
  protocol class (APR has its own `AprEndpoint`, not covered here).
