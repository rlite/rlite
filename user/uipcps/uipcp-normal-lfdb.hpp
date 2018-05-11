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
#include <memory>

#include "BaseRIB.pb.h"
#include "rlite/cpputils.hpp"

namespace rlite {

using NameId = std::string *;

class NameIdsManager {
    std::unordered_map<std::string, std::unique_ptr<std::string>> m;

    NameId GetId(const std::string &name)
    {
        const auto it = m.find(name);
        if (it != m.end()) {
            return it->second.get();
        }

        m[name] = utils::make_unique<std::string>(name);
        return m[name].get();
    }

    std::string GetName(NameId nid)
    {
        assert(nid != nullptr);
        return *nid;
    }
};

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

    struct DijkstraInfo {
        unsigned int dist;
        NodeId nhop;
    };

    /* Is Loop Free Alternate algorithm enabled ? */
    bool lfa_enabled;

    /* Be verbose on routing computations. */
    bool verbose = false;

public:
    LFDB(bool lfa_enabled, bool verbose = false)
        : lfa_enabled(lfa_enabled), verbose(verbose)
    {
    }

    /* Keeps a mapping between neighbor names (std::string objects) and
     * numerical ids (NameId). */
    NameIdsManager nim;

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
        std::unordered_map<NodeId, DijkstraInfo> &info);

    int compute_next_hops(const NodeId &local_node);

    /* Dump the routing table. */
    void dump_routing(std::stringstream &ss, const NodeId &local_node) const;

    /* Dump the lower flows database. */
    void dump(std::stringstream &ss) const;
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
