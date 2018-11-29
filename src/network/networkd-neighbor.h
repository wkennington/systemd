/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "conf-parser.h"
#include "in-addr-util.h"

typedef struct Neighbor Neighbor;

#include "networkd-link.h"
#include "networkd-network.h"

struct Neighbor {
        Network *network;
        Link *link;
        NetworkConfigSection *section;

        int family;
        union in_addr_union in_addr;
        struct ether_addr *mac;

        LIST_FIELDS(Neighbor, neighbors);
};

void neighbor_free(Neighbor *neighbor);

DEFINE_TRIVIAL_CLEANUP_FUNC(Neighbor*, neighbor_free);

int neighbor_configure(Neighbor *neighbor, Link *link, sd_netlink_message_handler_t callback, bool update);

CONFIG_PARSER_PROTOTYPE(config_parse_neighbor_address);
