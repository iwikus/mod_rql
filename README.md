# mod_protect

Apache HTTP Server request limiter.

The module limits concurrent HTTP requests using the Apache scoreboard as the source of truth.

## Configuration

```apache
LoadModule protect_module modules/mod_protect.so

ProtectMaxConcurrentPerIP 20
ProtectMaxConcurrentPerVHost 80
```

The concurrent limits apply to active HTTP requests, not TCP connections. A request is rejected with HTTP 429 when accepting it would exceed the configured limit.

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

Rate limits use shared memory protected by a process-shared mutex, so counters are shared across Apache worker processes. `ProtectURICount` uses Apache's normalized URI (`r->uri`), without the query string. `ProtectURIDynamicCount` adds a separate limit for dynamic handlers. The rate window is fixed: the configured number of requests is allowed and the next request is rejected with HTTP 429.

Dynamic request classification uses the Apache request handler rather than URL suffixes.
