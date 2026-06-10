# Custom CSP Filter for Liferay

Custom Content Security Policy (CSP) Filter module for Liferay 2025.q1 that modifies CSP headers based on domain.

## Features

- ✅ Executes **after** Liferay's default CSP filter
- ✅ Automatically detects domains starting with `partnerportal`
- ✅ Replaces nonce values with `unsafe-inline` for those domains
- ✅ Non-invasive: no modification of Liferay core files
- ✅ Modular and easy to deploy
- ✅ Java 21 compatible
- ✅ Liferay 2025.q1 compatible

## How it works

When a request comes from a domain starting with `partnerportal` (e.g., `partnerportal.example.com`):

1. The custom filter intercepts the HTTP response
2. It modifies the CSP headers set by Liferay's filter
3. All `nonce-*` values are replaced with `unsafe-inline`

### Example

**Original CSP Header (from Liferay):**
```
Content-Security-Policy: script-src 'nonce-ABC123def456'; style-src 'nonce-ABC123def456'
```

**Modified CSP Header (for partnerportal):**
```
Content-Security-Policy: script-src 'unsafe-inline'; style-src 'unsafe-inline'
```

## Project Structure

```
custom-csp-filter/
├── pom.xml                  # Maven configuration
├── bnd.bnd                  # OSGi bundle configuration
├── README.md                # This file
└── src/main/java/
    └── com/example/custom/csp/filter/
        └── CustomContentSecurityPolicyFilter.java
```

## Prerequisites

- Java 21+
- Maven 3.6+
- Liferay 2025.q1 with CSP enabled

## Build

```bash
mvn clean package
```

The compiled JAR will be created in `target/custom-csp-filter-1.0.0.jar`

## Deployment

### Option 1: Manual Deployment

Copy the JAR to Liferay's deploy folder:

```bash
cp target/custom-csp-filter-1.0.0.jar /path/to/liferay/deploy/
```

### Option 2: Docker

If using Docker, copy the JAR to your Docker volume or build directory before starting the container.

## Configuration

The domains list is hardcoded in the filter. To modify it:

1. Edit `src/main/java/com/example/custom/csp/filter/CustomContentSecurityPolicyFilter.java`
2. Modify the domain check in the `_modifyCspHeader()` method
3. Recompile and redeploy

### Current configuration

```java
if (serverName.startsWith("partnerportal")) {
    // Replace nonces with unsafe-inline
}
```

## Troubleshooting

### The filter is not being applied

1. Verify the JAR is deployed correctly
2. Check the Liferay logs for any errors
3. Ensure CSP is enabled in Liferay configuration
4. Verify the domain matches the pattern (starts with `partnerportal`)

### Debug logging

Enable debug logging to see the CSP modifications:

```
log4j.logger.com.example.custom.csp.filter=DEBUG
```

## Author

Eric Daniel

## License

MIT License