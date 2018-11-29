/* SPDX-License-Identifier: LGPL-2.1+ */
#include "networkd-neighbor.h"

void neighbor_free(Neighbor *neighbor) {
        if (!neighbor)
                return;

        if (neighbor->network) {
                LIST_REMOVE(neighbors, neighbor->network->neighbors, neighbor);
                assert(neighbor->network->n_neighbors > 0);
                neighbor->network->n_neighbors--;

                if (neighbor->section) {
                        hashmap_remove(neighbor->network->neighbors_by_section, neighbor->section);
                        network_config_section_free(neighbor->section);
                }
        }

        free(neighbor);
}

int neighbor_new_static(Network *network, const char *filename, unsigned section_line, Neighbor **ret) {
        _cleanup_(network_config_section_freep) NetworkConfigSection *n = NULL;
        _cleanup_(neighbor_freep) Neighbor *neighbor = NULL;
        int r;

        assert(network);
        assert(ret);
        assert(!!filename == (section_line > 0));

        if (filename) {
                r = network_config_section_new(filename, section_line, &n);
                if (r < 0)
                        return r;

                neighbor = hashmap_get(network->neighbors_by_section, n);
                if (neighbor) {
                        *ret = TAKE_PTR(neighbor);

                        return 0;
                }
        }

        neighbor = new(AddressLabel, 1);
        if (!neighbor)
                return -ENOMEM;

        *neighbor = (Neighbor) {
                .network = network,
                .family = AF_UNSPEC,
        };

        LIST_APPEND(neighbors, network->neighbors, neighbor);
        network->n_neighbors++;

        if (filename) {
                neighbor->section = TAKE_PTR(n);

                r = hashmap_ensure_allocated(&network->neighbors_by_section, &network_config_hash_ops);
                if (r < 0)
                        return r;

                r = hashmap_put(network->neighbors_by_section, neighbor->section, neighbor);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(neighbor);

        return 0;
}

int neighbor_configure(
                Neighbor *neighbor,
                Link *link,
                sd_netlink_message_handler_t callback,
                bool update) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        int r;

        assert(neighbor);
        assert(link);
        assert(link->ifindex > 0);
        assert(link->manager);
        assert(link->manager->rtnl);

        r = sd_rtnl_message_new_neigh(link->manager->rtnl, &req, RTM_NEWNEIGH,
                                          link->ifindex, neighbor->family);
        if (r < 0)
                return log_error_errno(r, "Could not allocate RTM_NEWNEIGH message: %m");

        r = sd_rtnl_message_neigh_set_state(req, NUD_PERMANENT);
        if (r < 0)
                return log_error_errno(r, "Could not set state: %m");

        r = sd_rtnl_message_set_flags(req, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Could not set flags: %m");

        r = sd_netlink_message_append_ether_addr(req, NDA_LLADDR, neighbor->mac);
        if (r < 0)
                return log_error_errno(r, "Could not append NDA_LLADDR attribute: %m");

        if (neighbor->family == AF_INET6) {
                r = sd_netlink_message_append_in6_addr(req, NDA_DST, &neighbor->in_addr.in6);
                if (r < 0)
                        return log_error_errno(r, "Could not append NDA_DST attribute: %m");
        } else if (neighbor->family == AF_INET) {
                r = sd_netlink_message_append_in_addr(req, NDA_DST, &neighbor->in_addr.in4);
                if (r < 0)
                        return log_error_errno(r, "Could not append NDA_DST attribute: %m");
        } else {
                return log_error_errno(-EINVAL, "Missing Neighbor Address");
        }

        r = sd_netlink_call_async(link->manager->rtnl, NULL, req, callback,
                                  link_netlink_destroy_callback, link, 0, __func__);
        if (r < 0)
                return log_error_errno(r, "Could not send rtnetlink message: %m");

        link_ref(link);

        return 0;
}

int config_parse_neighbor_address(const char *unit,
                                  const char *filename,
                                  unsigned line,
                                  const char *section,
                                  unsigned section_line,
                                  const char *lvalue,
                                  int ltype,
                                  const char *rvalue,
                                  void *data,
                                  void *userdata) {

        Network *network = userdata;
        _cleanup_(route_freep) Neighbor *n = NULL;
        union in_addr_union buffer;
        int r, f;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = neighbor_new_static(network, filename, section_line, &n);
        if (r < 0)
                return r;

        r = in_addr_from_string_auto(rvalue, &f, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, r, "Neighbor Address is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        n->family = f;
        n->in_addr = buffer;
        TAKE_PTR(n);

        return 0;
}
