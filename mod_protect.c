#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_log.h"

#include <stdlib.h>
#include <string.h>

#include "protect_scoreboard.h"

module AP_MODULE_DECLARE_DATA protect_module;

typedef struct {
    long max_concurrent_ip;
    long max_concurrent_vhost;
} protect_config;

static void *protect_create_server_config(apr_pool_t *p, server_rec *s)
{
    protect_config *cfg = apr_pcalloc(p, sizeof(*cfg));
    (void)s;
    cfg->max_concurrent_ip = 0;
    cfg->max_concurrent_vhost = 0;
    return cfg;
}

static const char *protect_set_limit(cmd_parms *cmd, void *dummy,
                                     const char *arg)
{
    protect_config *cfg = ap_get_module_config(cmd->server->module_config,
                                               &protect_module);
    char *end;
    long value;

    (void)dummy;

    value = strtol(arg, &end, 10);
    if (*arg == '\0' || *end != '\0' || value < 0) {
        return "mod_protect: limit must be a non-negative integer";
    }

    if (!strcmp(cmd->cmd->name, "ProtectMaxConcurrentPerIP")) {
        cfg->max_concurrent_ip = value;
    }
    else if (!strcmp(cmd->cmd->name, "ProtectMaxConcurrentPerVHost")) {
        cfg->max_concurrent_vhost = value;
    }

    return NULL;
}

static int protect_fixups(request_rec *r)
{
    protect_config *cfg;
    protect_scoreboard_counts counts;
    int rv;

    if (!r->connection || !r->connection->client_ip ||
        !ap_is_initial_req(r)) {
        return DECLINED;
    }

    cfg = ap_get_module_config(r->server->module_config, &protect_module);

    if (!cfg->max_concurrent_ip && !cfg->max_concurrent_vhost) {
        return DECLINED;
    }

    rv = protect_scoreboard_count(r, &counts);
    if (rv != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10001)
                      "mod_protect: scoreboard unavailable");
        return DECLINED;
    }

    if ((cfg->max_concurrent_ip &&
         counts.ip > (unsigned long)cfg->max_concurrent_ip) ||
        (cfg->max_concurrent_vhost &&
         counts.vhost > (unsigned long)cfg->max_concurrent_vhost)) {

        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, APLOGNO(10002)
                      "mod_protect: request limit exceeded: ip=%s vhost=%s "
                      "ip=%lu vhost=%lu",
                      r->connection->client_ip,
                      r->server->server_hostname ?
                          r->server->server_hostname : "-",
                      counts.ip, counts.vhost);

        return HTTP_TOO_MANY_REQUESTS;
    }

    return DECLINED;
}

static const command_rec protect_cmds[] = {
    AP_INIT_TAKE1("ProtectMaxConcurrentPerIP", protect_set_limit, NULL,
                  RSRC_CONF,
                  "Maximum concurrent requests per client IP"),
    AP_INIT_TAKE1("ProtectMaxConcurrentPerVHost", protect_set_limit, NULL,
                  RSRC_CONF,
                  "Maximum concurrent requests per virtual host"),
    { NULL }
};

static void protect_register_hooks(apr_pool_t *p)
{
    (void)p;
    ap_hook_fixups(protect_fixups, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA protect_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    protect_create_server_config,
    NULL,
    protect_cmds,
    protect_register_hooks
};
