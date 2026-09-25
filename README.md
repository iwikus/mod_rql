# mod_rql

Apache HTTP Server request limiter.

The module limits concurrent requests using the Apache scoreboard as the source of truth. It can limit requests globally, per client IP, per virtual host, and per IP + virtual host.

## Current status

Initial development. The first implementation focuses on correct scoreboard-based concurrent-request accounting.

## Build

Requires Apache 2.4 development headers and `apxs`.

```sh
apxs -c -I. mod_rql.c rql_scoreboard.c
apxs -i -a mod_rql.la
```

## Configuration

```apache
LoadModule rql_module modules/mod_rql.so

RQLMaxActiveRequests 100
RQLMaxActiveRequestsPerIP 20
RQLMaxActiveRequestsPerVHost 80
RQLMaxActiveRequestsPerIPVHost 10
```

A configured limit is inclusive: a request is rejected with HTTP 429 when accepting it would exceed the configured concurrent-request limit.

Rate limiting will be added separately.

## Design

Concurrent request accounting is based on the Apache scoreboard and uses the public `ap_copy_scoreboard_worker()` API. No TCP connection counting and no HTTP polling of `/server-status` are used.

Dynamic request classification will use the Apache request handler (PHP/CGI/FCGI) rather than URL suffixes.
