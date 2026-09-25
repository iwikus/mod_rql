#ifndef MOD_PROTECT_RATE_H
#define MOD_PROTECT_RATE_H

#include "httpd.h"
#include "http_request.h"

typedef struct {
    long uri_count;
    long uri_interval;
    long uri_dynamic_count;
    long uri_dynamic_interval;
    long site_count;
    long site_interval;
} protect_rate_config;

int protect_rate_check(request_rec *r, const protect_rate_config *cfg,
                       int *limited);

int protect_rate_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s);

#endif
