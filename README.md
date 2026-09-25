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

Planned request-rate protection follows the terminology used by mod_evasive:

```apache
ProtectPageCount 20
ProtectPageInterval 1

ProtectPageDynamicCount 10
ProtectPageDynamicInterval 1

ProtectSiteCount 100
ProtectSiteInterval 1
```

## Design

Concurrent request accounting is based on the Apache scoreboard and uses the public `ap_copy_scoreboard_worker()` API. No TCP connection counting and no HTTP polling of `/server-status` are used.

Dynamic request classification will use the Apache request handler (PHP/CGI/FCGI) rather than URL suffixes.
