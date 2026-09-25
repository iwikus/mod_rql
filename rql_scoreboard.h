#ifndef MOD_RQL_SCOREBOARD_H
#define MOD_RQL_SCOREBOARD_H

#include "httpd.h"
#include "scoreboard.h"

typedef struct {
    unsigned long global;
    unsigned long ip;
    unsigned long vhost;
    unsigned long ip_vhost;
} rql_scoreboard_counts;

int rql_scoreboard_count(request_rec *r, rql_scoreboard_counts *counts);

#endif
