# mod_protect

Apache HTTP Server request limiter.

The module limits concurrent HTTP requests using the Apache scoreboard as the source of truth.

## Configuration

```apache
LoadModule protect_module modules/mod_protect.so

ProtectMaxConcurrentPerIP 20
ProtectMaxConcurrentPerVHost 80

# Optional additional log containing only requests rejected by mod_protect.
# The Apache user must be able to write this file.
ProtectLog /var/log/apache2/protect.log
```

The concurrent limits apply to active HTTP requests, not TCP connections. The Apache scoreboard is checked at request fixup time. A request is rejected with HTTP 429 when the configured limit would be exceeded. With a limit of 20, requests 1–20 are allowed and the 21st active request is rejected.

For concurrent accounting, the module counts only scoreboard workers in `SERVER_BUSY_READ`, `SERVER_BUSY_WRITE`, or `SERVER_BUSY_DNS` state. Keepalive, logging, closing, ready, and other non-active states are not counted. `ProtectMaxConcurrentPerIP` counts active requests from the effective client IP; `ProtectMaxConcurrentPerVHost` counts active requests for the current virtual host.

`ProtectLog` is optional. When configured, every request rejected by a concurrent or request-rate limit is also appended to that file. The normal Apache error log is still used as before.

Request-rate protection uses per-client-IP counters:

```apache
ProtectURICount 20
ProtectURIInterval 1

ProtectURIDynamicCount 10
ProtectURIDynamicInterval 1

ProtectSiteCount 100
ProtectSiteInterval 1
```

## Design

Concurrent request accounting is based on the Apache scoreboard and uses the public `ap_copy_scoreboard_worker()` API. No TCP connection counting and no HTTP polling of `/server-status` are used.

Rate limits use shared memory protected by a process-shared mutex, so counters are shared across Apache worker processes. `ProtectURICount` uses Apache's normalized URI (`r->uri`), without the query string. `ProtectURIDynamicCount` adds a separate limit for dynamic handlers. The rate window is fixed: the configured number of requests is allowed and the next request is rejected with HTTP 429. `ProtectURICount` and `ProtectURIDynamicCount` are keyed by effective client IP and normalized URI; `ProtectSiteCount` is keyed by effective client IP and virtual host. The query string is not part of the URI key.

Dynamic request classification uses the Apache request handler rather than URL suffixes. It includes CGI, FCGI, proxy/FCGI handlers, and mod_php handlers such as `application/x-httpd-php`.
