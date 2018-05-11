/*
 * Lower Flows database and next hops computation.
 *
 * Copyright (C) 2018 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <string>
#include <list>
#include <unordered_map>

namespace rlite {

using NodeId = std::string;

/* The Lower Flows database, with functionalities to compute the next hops,
 * i.e. the Dijkstra algorithm. This has also optional support for the Loop
 * Free Alternate algorithm. */
struct LFDB {
    struct Edge {
        NodeId to;
        unsigned int cost;

        Edge(const NodeId &to_, unsigned int cost_) : to(to_), cost(cost_) {}
        Edge(Edge &&) = default;
    };

    struct Info {
        unsigned int dist;
        NodeId nhop;
        bool visited;
    };

    /* Is Loop Free Alternate algorithm enabled ? */
    bool lfa_enabled;

    bool verbose = false;

public:
    LFDB(bool lfa_enabled, bool verbose = false)
        : lfa_enabled(lfa_enabled), verbose(verbose)
    {
    }

    /* Lower Flow Database. */
    std::unordered_map<NodeId, std::unordered_map<NodeId, gpb::LowerFlow>> db;

    /* The routing table computed by compute_next_hops(), or statically
     * updated. */
    std::unordered_map<NodeId, std::list<NodeId>> next_hops;
    NodeId dflt_nhop;

    const gpb::LowerFlow *find(const NodeId &local_node,
                               const NodeId &remote_node) const
    {
        return _find(local_node, remote_node);
    };
    gpb::LowerFlow *find(const NodeId &local_node, const NodeId &remote_node);
    const gpb::LowerFlow *_find(const NodeId &local_node,
                                const NodeId &remote_node) const;

    void compute_shortest_paths(
        const NodeId &source_node,
        const std::unordered_map<NodeId, std::list<Edge>> &graph,
        std::unordered_map<NodeId, Info> &info);

    int compute_next_hops(const NodeId &local_node);

    /* Dump the routing table. */
    void dump(std::stringstream &ss, const NodeId &local_node) const;
};

/* Helper for pretty printing of default route. */
static inline std::string
node_id_pretty(const NodeId &node)
{
    if (node == std::string()) {
        return std::string("any");
    }
    return node;
}

} // namespace rlite
