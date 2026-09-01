# tomcat-ip-filter

A minimal Gradle project that builds a custom Tomcat NIO endpoint
(`FilteringNioEndpoint`) which rejects connections from blocked IPs (with an optional allow list to bypass block-list checks) at
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

The file can contain one IP per line. Blank lines and comments starting with `#` are ignored (inline comments and extra whitespace are also stripped). 

If an allowed IPs file is configured, any connection from an IP present on the allow list will be permitted immediately, bypassing the block list check. If an IP is not on the allow list, it is still checked against the block list and permitted unless explicitly blocked.

The IP files are monitored for changes; if you modify the files while Tomcat is running, the changes will be automatically detected and reloaded without requiring a restart.

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

## Notes

- Only tested against the NIO connector (`Http11NioProtocol` /
  `NioEndpoint`). If APR/native is enabled on your server, this won't
  be used unless you also point the connector explicitly at the NIO
  protocol class (APR has its own `AprEndpoint`, not covered here).
- If Tomcat sits behind a reverse proxy or load balancer, the IP seen
  by `serverSocketAccept()` is the proxy's IP, not the original
  client's — this only blocks by the IP that opens the TCP connection
  directly to Tomcat.
