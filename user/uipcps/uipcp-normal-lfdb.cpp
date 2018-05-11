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
#include <sstream>
#include <iostream>

#include "BaseRIB.pb.h"
#include "uipcp-normal-lfdb.hpp"

namespace rlite {

void
LFDB::dump(std::stringstream &ss) const
{
    ss << "Lower Flow Database:" << std::endl;
    for (const auto &kvi : db) {
        for (const auto &kvj : kvi.second) {
            const gpb::LowerFlow &flow = kvj.second;

            ss << "    Local: " << flow.local_node()
               << ", Remote: " << flow.remote_node()
               << ", Cost: " << flow.cost() << ", Seqnum: " << flow.seqnum()
               << ", State: " << flow.state() << ", Age: " << flow.age()
               << std::endl;
        }
    }

    ss << std::endl;
}

void
LFDB::dump_routing(std::stringstream &ss, const NodeId &local_node) const
{
    ss << "Routing table for node " << local_node << ":" << std::endl;
    for (const auto &kvr : next_hops) {
        std::string dst_node = kvr.first;

        if (dst_node.size() && kvr.second.size() == 1 &&
            kvr.second.front() == dflt_nhop) {
            /* Hide this entry, as it is covered by the default one. */
            continue;
        }

        ss << "    Remote: " << node_id_pretty(dst_node) << ", Next hops: ";
        for (auto lfa = kvr.second.begin();;) {
            ss << *lfa;
            if (++lfa == kvr.second.end()) {
                break;
            }
            ss << " ";
        }
        ss << std::endl;
    }
}

void
LFDB::compute_shortest_paths(
    const NodeId &source_node,
    const std::unordered_map<NodeId, std::list<Edge>> &graph,
    std::unordered_map<NodeId, Info> &info)
{
    /* Initialize the per-node info map. */
    for (const auto &kvg : graph) {
        struct Info inf;

        inf.dist    = UINT_MAX;
        inf.visited = false;

        info[kvg.first] = inf;
    }
    info[source_node].dist = 0;

    for (;;) {
        NodeId min_node;
        unsigned int min_dist = UINT_MAX;

        /* Select the closest node from the ones in the frontier. */
        for (auto &kvi : info) {
            if (!kvi.second.visited && kvi.second.dist < min_dist) {
                min_node = kvi.first;
                min_dist = kvi.second.dist;
            }
        }

        if (min_dist == UINT_MAX) {
            break;
        }

        assert(!min_node.empty());

        if (verbose) {
            std::cout << "Selecting node " << min_node << std::endl;
        }

        if (!graph.count(min_node)) {
            continue; /* nothing to do */
        }

        const std::list<Edge> &edges = graph.at(min_node);
        Info &info_min               = info[min_node];

        info_min.visited = true;

        for (const Edge &edge : edges) {
            Info &info_to = info[edge.to];

            if (info_to.dist > info_min.dist + edge.cost) {
                info_to.dist = info_min.dist + edge.cost;
                info_to.nhop =
                    (min_node == source_node) ? edge.to : info_min.nhop;
            }
        }
    }

    if (verbose) {
        std::cout << "Dijkstra result:" << std::endl;
        for (const auto &kvi : info) {
            std::cout << "    Node: " << kvi.first
                      << ", Dist: " << kvi.second.dist << ", Visited "
                      << kvi.second.visited << std::endl;
        }
    }
}

int
LFDB::compute_next_hops(const NodeId &local_node)
{
    std::unordered_map<NodeId, std::unordered_map<NodeId, Info>> neigh_infos;
    std::unordered_map<NodeId, std::list<Edge>> graph;
    std::unordered_map<NodeId, Info> info;

    /* Clean up state left from the previous run. */
    next_hops.clear();

    /* Build the graph from the Lower Flow Database. */
    graph[local_node] = std::list<Edge>();
    for (const auto &kvi : db) {
        for (const auto &kvj : kvi.second) {
            const gpb::LowerFlow *revlf;

            revlf = find(kvj.second.local_node(), kvj.second.remote_node());

            if (revlf == nullptr || revlf->cost() != kvj.second.cost()) {
                /* Something is wrong, this could be malicious or erroneous. */
                continue;
            }

            graph[kvj.second.local_node()].emplace_back(
                kvj.second.remote_node(), kvj.second.cost());
            if (!graph.count(kvj.second.remote_node())) {
                /* Make sure graph contains all the nodes, even if with
                 * empty lists. */
                graph[kvj.second.remote_node()] = std::list<Edge>();
            }
        }
    }

    if (verbose) {
        std::cout << "Graph [" << db.size() << " nodes]:" << std::endl;
        for (const auto &kvg : graph) {
            std::cout << kvg.first << ": {";
            for (const Edge &edge : kvg.second) {
                std::cout << "(" << edge.to << "," << edge.cost << "), ";
            }
            std::cout << "}" << std::endl;
        }
    }

    /* Compute shortest paths rooted at the local node, and use the
     * result to fill in the next_hops routing table. */
    compute_shortest_paths(local_node, graph, info);
    for (const auto &kvi : info) {
        if (kvi.first == local_node || !kvi.second.visited) {
            /* I don't need a next hop for myself. */
            continue;
        }
        next_hops[kvi.first].push_back(kvi.second.nhop);
    }

    if (lfa_enabled) {
        /* Compute the shortest paths rooted at each neighbor of the local
         * node, storing the results into neigh_infos. */
        for (const Edge &edge : graph[local_node]) {
            compute_shortest_paths(edge.to, graph, neigh_infos[edge.to]);
        }

        /* For each node V other than the local node ... */
        for (const auto &kvv : graph) {
            if (kvv.first == local_node) {
                continue;
            }

            /* For each neighbor U of the local node, excluding U ... */
            for (const auto &kvu : neigh_infos) {
                if (kvu.first == kvv.first) {
                    continue;
                }

                /* dist(U, V) < dist(U, local) + dist(local, V) */
                if (neigh_infos[kvu.first][kvv.first].dist <
                    neigh_infos[kvu.first][local_node].dist +
                        info[kvv.first].dist) {
                    bool dupl = false;

                    for (const NodeId &lfa : next_hops[kvv.first]) {
                        if (lfa == kvu.first) {
                            dupl = true;
                            break;
                        }
                    }

                    if (!dupl) {
                        next_hops[kvv.first].push_back(kvu.first);
                    }
                }
            }
        }
    }

    if (verbose) {
        std::stringstream ss;

        dump_routing(ss, local_node);
        std::cout << ss.str();
    }

    return 0;
}

gpb::LowerFlow *
LFDB::find(const NodeId &local_node, const NodeId &remote_node)
{
    const gpb::LowerFlow *lf = _find(local_node, remote_node);
    return const_cast<gpb::LowerFlow *>(lf);
}

const gpb::LowerFlow *
LFDB::_find(const NodeId &local_node, const NodeId &remote_node) const
{
    const auto it = db.find(local_node);
    std::unordered_map<NodeId, gpb::LowerFlow>::const_iterator jt;

    if (it == db.end()) {
        return nullptr;
    }

    jt = it->second.find(remote_node);

    return jt == it->second.end() ? nullptr : &jt->second;
}

} // namespace rlite
