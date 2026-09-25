#include "rql_scoreboard.h"

#include <string.h>

static int rql_scoreboard_request_active(unsigned char status)
{
    switch (status) {
    case SERVER_BUSY_READ:
    case SERVER_BUSY_WRITE:
    case SERVER_BUSY_DNS:
        return 1;
    default:
        return 0;
    }
}

int rql_scoreboard_count(request_rec *r, rql_scoreboard_counts *counts)
{
    global_score *global;
    int i, j;

    if (!counts || !r) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    memset(counts, 0, sizeof(*counts));

    if (!ap_exists_scoreboard_image()) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    global = ap_get_scoreboard_global();
    if (!global) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    for (i = 0; i < global->server_limit; ++i) {
        for (j = 0; j < global->thread_limit; ++j) {
            worker_score ws;

            ap_copy_scoreboard_worker(&ws, i, j);

            if (!rql_scoreboard_request_active(ws.status)) {
                continue;
            }

            ++counts->global;

            if (r->connection && r->connection->client_ip &&
                ws.client64[0] &&
                strcmp(r->connection->client_ip, ws.client64) == 0) {
                ++counts->ip;
            }

            if (r->server && r->server->server_hostname &&
                ws.vhost[0] &&
                strcmp(r->server->server_hostname, ws.vhost) == 0) {
                ++counts->vhost;

                if (r->connection && r->connection->client_ip &&
                    ws.client64[0] &&
                    strcmp(r->connection->client_ip, ws.client64) == 0) {
                    ++counts->ip_vhost;
                }
            }
        }
    }

    return OK;
}
