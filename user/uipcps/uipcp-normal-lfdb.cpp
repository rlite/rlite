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
#include <queue>
#include <limits>

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
               << ", Total Bandwidth: " << flow.bw_total()
               << ", Free Bandwidth: " << flow.bw_free() << std::endl;
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
    const std::unordered_map<NodeId, std::vector<Edge>> &graph,
    std::unordered_map<NodeId, DijkstraInfo> &info)
{
    /* Per-node info stored in the priority queue. */
    struct PQInfo {
        NodeId node;
        unsigned int dist;
        PQInfo(const NodeId &node, unsigned int dist) : node(node), dist(dist)
        {
        }
        bool operator<(const PQInfo &other) const { return dist > other.dist; }
    };
    std::priority_queue<PQInfo> frontier;

    /* Initialize the per-node info map. */
    for (const auto &kvg : graph) {
        struct DijkstraInfo inf;

        inf.dist        = std::numeric_limits<unsigned int>::max();
        info[kvg.first] = std::move(inf);
    }

    frontier.push({source_node, 0});
    while (!frontier.empty()) {
        /* Select the closest node from the ones in the frontier. */
        PQInfo closer = frontier.top();
        frontier.pop();

        if (closer.dist == std::numeric_limits<unsigned int>::max()) {
            break;
        }

        DijkstraInfo &info_min = info[closer.node];
        info_min.dist          = closer.dist;

        if (verbose) {
            std::cout << "Selecting node " << closer.node << std::endl;
        }

        auto graphit = graph.find(closer.node);
        if (graphit == graph.end()) {
            continue; /* nothing to do */
        }

        const std::vector<Edge> &edges = graphit->second;

        /* Apply relaxation rule and update the frontier. */
        for (const Edge &edge : edges) {
            DijkstraInfo &info_to = info[edge.to];

            if (info_to.dist > info_min.dist + edge.cost) {
                info_to.dist = info_min.dist + edge.cost;
                info_to.nhop =
                    (closer.node == source_node) ? edge.to : info_min.nhop;
                frontier.push({edge.to, info_to.dist});
            }
        }
    }

    if (verbose) {
        std::cout << "Dijkstra result:" << std::endl;
        for (const auto &kvi : info) {
            std::cout << "    Node: " << kvi.first
                      << ", Dist: " << kvi.second.dist << std::endl;
        }
    }
}

int
LFDB::compute_next_hops(const NodeId &local_node)
{
    std::unordered_map<NodeId, std::unordered_map<NodeId, DijkstraInfo>>
        neigh_infos;
    std::unordered_map<NodeId, std::vector<Edge>> graph;
    std::unordered_map<NodeId, DijkstraInfo> info;

    /* Clean up state left from the previous run. */
    next_hops.clear();

    /* Build the graph from the Lower Flow Database. */
    graph[local_node] = std::vector<Edge>();
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
                graph[kvj.second.remote_node()] = std::vector<Edge>();
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
        if (kvi.first == local_node ||
            kvi.second.dist == std::numeric_limits<unsigned int>::max()) {
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

std::vector<NodeId>
LFDB::compute_max_flow(
    const NodeId &src_node, const NodeId &dest_node,
    const std::unordered_map<NodeId, std::vector<Edge>> &graph,
    const unsigned int req_flow)
{
    /* A variation of the Edmonds-Karp algorithm.
     * We're not interested in total maximum flow, but in the shortest
     * augumenting path that has enough capacity. */

    std::queue<NodeId> q;
    q.push(src_node);
    std::unordered_map<NodeId, Edge> pred;
    bool found = false;

    while (!found && !q.empty()) {
        NodeId cur = q.front();
        q.pop();
        auto graphit                   = graph.find(cur);
        const std::vector<Edge> &edges = graphit->second;

        for (const Edge &edge : edges) {
            if (pred.find(edge.to) == pred.end() &&
                (pred.find(cur) == pred.end() ||
                 edge.to != pred.find(cur)->second.to) &&
                edge.capacity >= req_flow) {
                pred.emplace(edge.to, Edge(cur, edge.cost));
                q.push(edge.to);
                if (edge.to == dest_node) {
                    found = true;
                }
            }
        }
    }

    std::vector<NodeId> path;

    if (pred.find(dest_node) != pred.end()) {
        path.insert(path.begin(), dest_node);
        for (auto e = pred.find(dest_node); e != pred.end();
             e      = pred.find(e->second.to)) {
            path.insert(path.begin(), e->second.to);
        }
    }

    if (verbose) {
        if (path.size()) {
            std::cout << "Found path [" << path.size()
                      << " nodes]:" << std::endl;
            for (auto e : path) {
                std::cout << e << ",";
            }
            std::cout << std::endl;
        } else {
            std::cout << "Path not found" << std::endl;
        }
    }

    return path;
}

std::vector<NodeId>
LFDB::find_flow_path(const NodeId &src_node, const NodeId &dest_node,
                     const unsigned int req_flow)
{
    std::vector<NodeId> ret;

    if (src_node == dest_node) {
        return ret;
    }

    std::unordered_map<NodeId, std::unordered_map<NodeId, DijkstraInfo>>
        neigh_infos;
    std::unordered_map<NodeId, std::vector<Edge>> graph;

    /* Clean up state left from the previous run. */
    next_hops.clear();

    /* Build the graph from the Lower Flow Database. */
    graph[src_node] = std::vector<Edge>();
    for (const auto &kvi : db) {
        for (const auto &kvj : kvi.second) {
            const gpb::LowerFlow *revlf;

            revlf = find(kvj.second.local_node(), kvj.second.remote_node());

            if (revlf == nullptr || revlf->cost() != kvj.second.cost()) {
                /* Something is wrong, this could be malicious or erroneous. */
                continue;
            }

            graph[kvj.second.local_node()].emplace_back(
                kvj.second.remote_node(), kvj.second.cost(),
                kvj.second.bw_free());
            if (!graph.count(kvj.second.remote_node())) {
                /* Make sure graph contains all the nodes, even if with
                 * empty lists. */
                graph[kvj.second.remote_node()] = std::vector<Edge>();
            }
        }
    }

    if (verbose) {
        std::cout << "Graph [" << db.size() << " nodes]:" << std::endl;
        for (const auto &kvg : graph) {
            std::cout << kvg.first << ": {";
            for (const Edge &edge : kvg.second) {
                std::cout << "(" << edge.to << "," << edge.cost << ","
                          << edge.capacity << "), ";
            }
            std::cout << "}" << std::endl;
        }
    }

    ret = compute_max_flow(src_node, dest_node, graph, req_flow);

    if (verbose) {
        std::stringstream ss;

        dump_routing(ss, src_node);
        std::cout << ss.str();
    }

    return ret;
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
