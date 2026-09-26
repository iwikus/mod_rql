# mod_protect

Apache HTTP Server module for limiting concurrent requests and request rates by client IP, URI and virtual host.

## Requirements

- Apache HTTP Server 2.4
- Apache scoreboard with `ExtendedStatus On` for concurrent request limits
- APR shared memory and process-shared mutex support for rate limits

## Loading

```apache
LoadModule protect_module modules/mod_protect.so
```

## Directives

### ProtectMaxConcurrentPerIP

```apache
ProtectMaxConcurrentPerIP number
```

Limits the number of concurrently active HTTP requests from one client IP address.

The limit applies across all virtual hosts.

### ProtectMaxConcurrentPerVHost

```apache
ProtectMaxConcurrentPerVHost number
```

Limits the number of concurrently active HTTP requests to the current virtual host.

### ProtectURICount

```apache
ProtectURICount number
```

Limits the number of requests from one client IP to one URI within the configured ProtectURIInterval.

The URI is Apache's normalized request URI. The query string is not included.

### ProtectURIInterval

```apache
ProtectURIInterval seconds
```

Sets the fixed time window used by ProtectURICount.

### ProtectURIDynamicCount

```apache
ProtectURIDynamicCount number
```

Sets an additional request limit for dynamic requests to one URI.

The limit is independent of ProtectURICount.

Dynamic requests are identified by the Apache request handler rather than by the URI or file name.

### ProtectURIDynamicInterval

```apache
ProtectURIDynamicInterval seconds
```

Sets the fixed time window used by ProtectURIDynamicCount.

### ProtectSiteCount

```apache
ProtectSiteCount number
```

Limits the number of requests from one client IP to one virtual host within the configured ProtectSiteInterval.

### ProtectSiteInterval

```apache
ProtectSiteInterval seconds
```

Sets the fixed time window used by ProtectSiteCount.

## Request handling

When a configured limit is exceeded, mod_protect rejects the request with HTTP status 429 Too Many Requests.

Concurrent limits apply to active HTTP requests. They are not TCP connection limits and are not rate limits.

Concurrent limits are evaluated using the Apache scoreboard.

Rate limits use fixed time windows. The configured number of requests is allowed during the window; the next request is rejected.

Concurrent and rate limits are independent and can be used together.

## Error log

When a concurrent request limit is exceeded, mod_protect writes a notice to the Apache error log:

```text
mod_protect: concurrent request limit exceeded: ip=192.0.2.10 vhost=www.example.com ip=21 vhost=5
```

When a request-rate limit is exceeded, mod_protect writes:

```text
mod_protect: request rate limit exceeded: ip=192.0.2.10 uri=/api/test
```

These messages are logged at notice level.

The log level can be changed using Apache's LogLevel directive, for example:

```apache
LogLevel protect:debug
```

## Rate limiting

Rate counters are shared between Apache worker processes using APR shared memory and a process-shared mutex.

The module uses:

```text
logs/protect-rates.shm
logs/protect-rates.lock
```

There are 16384 entries per rate-limit category.

Rate-limit keys use FNV-1a 64-bit hashing with linear probing.

If the rate-limit table is full, the module fails open.

## Concurrent request accounting

Concurrent request limits use the Apache scoreboard as the source of truth.

The module uses Apache's public scoreboard API. It does not maintain a separate concurrent-request counter and does not poll /server-status.

The Apache scoreboard is created and maintained by Apache.

## Configuration example

```apache
LoadModule status_module modules/mod_status.so
LoadModule protect_module modules/mod_protect.so

ExtendedStatus On

LogLevel protect:debug

ProtectURICount 100
ProtectURIInterval 10

ProtectURIDynamicCount 20
ProtectURIDynamicInterval 5

ProtectSiteCount 300
ProtectSiteInterval 1

ProtectMaxConcurrentPerIP 10
ProtectMaxConcurrentPerVHost 20
```

## Build

Build using apxs:

```sh
apxs -c -I. mod_protect.c protect_scoreboard.c protect_rate.c
```

Install:

```sh
apxs -i -a mod_protect.la
```

Or use the included Makefile:

```sh
make
make install
```

## Files

```text
mod_protect.c
protect_scoreboard.c
protect_scoreboard.h
protect_rate.c
protect_rate.h
Makefile
```

## Response

Requests rejected by mod_protect receive HTTP status 429 Too Many Requests.

The module does not generate a response body.
