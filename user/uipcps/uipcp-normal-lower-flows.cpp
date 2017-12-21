/*
 * Management of N-1 ports for normal uipcps, including routing.
 *
 * Copyright (C) 2015-2017 Nextworks
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

#include <climits>
#include <cerrno>
#include <sstream>
#include <iostream>

#include "uipcp-normal.hpp"

using namespace std;

class RoutingEngine {
public:
    RL_NODEFAULT_NONCOPIABLE(RoutingEngine);
    RoutingEngine(struct uipcp_rib *r) : lfa_enabled(false), rib(r) {}

    /* Recompute routing and forwarding table and possibly
     * update kernel forwarding data structures. */
    void update_kernel_routing(const NodeId &);

    void flow_state_update(struct rl_kmsg_flow_state *upd);

    /* Is Loop Free Alternate algorithm enabled ? */
    bool lfa_enabled;

    /* Dump the routing table. */
    void dump(std::stringstream &ss) const;

private:
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

    /* Step 1. Shortest Path algorithm. */
    void compute_shortest_paths(
        const NodeId &source_node,
        const std::unordered_map<NodeId, std::list<Edge>> &graph,
        std::unordered_map<NodeId, Info> &info);
    int compute_next_hops(const NodeId &);

    /* Step 3. Forwarding table computation and kernel update. */
    int compute_fwd_table();

    /* The routing table computed by compute_next_hops(). */
    std::unordered_map<NodeId, std::list<NodeId>> next_hops;
    NodeId dflt_nhop;

    /* The forwarding table computed by compute_fwd_table().
     * It maps a NodeId --> (dst_addr, local_port). */
    std::unordered_map<rlm_addr_t, std::pair<NodeId, rl_port_t>> next_ports;

    /* Set of ports that are currently down. */
    std::unordered_set<rl_port_t> ports_down;

    struct uipcp_rib *rib;
};

class FullyReplicatedLFDB : public LFDB {
    /* Lower Flow Database. */
    std::unordered_map<NodeId, std::unordered_map<NodeId, LowerFlow>> db;
    friend class RoutingEngine;

public:
    /* Routing engine. */
    RoutingEngine re;

    RL_NODEFAULT_NONCOPIABLE(FullyReplicatedLFDB);
    FullyReplicatedLFDB(struct uipcp_rib *_ur) : LFDB(_ur), re(_ur) {}
    ~FullyReplicatedLFDB() {}

    void dump(std::stringstream &ss) const override;
    void dump_routing(std::stringstream &ss) const override;

    const LowerFlow *find(const NodeId &local_node,
                          const NodeId &remote_node) const override
    {
        return _find(local_node, remote_node);
    };
    LowerFlow *find(const NodeId &local_node,
                    const NodeId &remote_node) override;
    bool add(const LowerFlow &lf) override;
    bool del(const NodeId &local_node, const NodeId &remote_node) override;
    void update_local(const std::string &neigh_name) override;
    void update_routing() override;
    int flow_state_update(struct rl_kmsg_flow_state *upd) override;

    const LowerFlow *_find(const NodeId &local_node,
                           const NodeId &remote_node) const;

    int rib_handler(const CDAPMessage *rm, NeighFlow *nf) override;

    int sync_neigh(NeighFlow *nf, unsigned int limit) const override;
    int neighs_refresh(size_t limit) override;
    void age_incr() override;
};

LowerFlow *
FullyReplicatedLFDB::find(const NodeId &local_node, const NodeId &remote_node)
{
    const LowerFlow *lf = _find(local_node, remote_node);
    return const_cast<LowerFlow *>(lf);
}

const LowerFlow *
FullyReplicatedLFDB::_find(const NodeId &local_node,
                           const NodeId &remote_node) const
{
    const auto it = db.find(local_node);
    unordered_map<NodeId, LowerFlow>::const_iterator jt;

    if (it == db.end()) {
        return nullptr;
    }

    jt = it->second.find(remote_node);

    return jt == it->second.end() ? nullptr : &jt->second;
}

/* The add method has overwrite semantic, and possibly resets the age.
 * Returns true if something changed. */
bool
FullyReplicatedLFDB::add(const LowerFlow &lf)
{
    auto it       = db.find(lf.local_node);
    string repr   = static_cast<string>(lf);
    LowerFlow lfz = lf;
    bool local_entry;

    lfz.age = 0;

    if (it == db.end() || it->second.count(lf.remote_node) == 0) {
        /* Not there, we need to add the entry. */
        db[lf.local_node][lf.remote_node] = lfz;
        UPD(rib->uipcp, "Lower flow %s added\n", repr.c_str());
        return true;
    }

    /* Entry is already there. Update if needed (this expression
     * was obtained by means of a Karnaugh map on three variables:
     * local, newer, equal). */
    local_entry = (lfz.local_node == rib->myname);
    if ((!local_entry && lfz.seqnum > it->second[lfz.remote_node].seqnum) ||
        (local_entry && lfz != it->second[lfz.remote_node])) {
        it->second[lfz.remote_node] = std::move(lfz); /* Update the entry */
        UPV(rib->uipcp, "Lower flow %s updated\n", repr.c_str());
        return true;
    }

    return false;
}

/* Returns true if something changed. */
bool
FullyReplicatedLFDB::del(const NodeId &local_node, const NodeId &remote_node)
{
    auto it = db.find(local_node);
    unordered_map<NodeId, LowerFlow>::iterator jt;
    string repr;

    if (it == db.end()) {
        return false;
    }

    jt = it->second.find(remote_node);

    if (jt == it->second.end()) {
        return false;
    }
    repr = static_cast<string>(jt->second);

    it->second.erase(jt);

    UPD(rib->uipcp, "Lower flow %s removed\n", repr.c_str());

    return true;
}

void
FullyReplicatedLFDB::update_local(const string &node_name)
{
    LowerFlowList lfl;
    LowerFlow lf;
    std::unique_ptr<CDAPMessage> sm;

    if (rib->get_neighbor(node_name, false) == nullptr) {
        return; /* Not our neighbor. */
    }

    lf.local_node  = rib->myname;
    lf.remote_node = node_name;
    lf.cost        = 1;
    lf.seqnum      = 1; /* not meaningful */
    lf.state       = true;
    lf.age         = 0;
    lfl.flows.push_back(std::move(lf));

    sm = make_unique<CDAPMessage>();
    sm->m_create(obj_class::lfdb, obj_name::lfdb);
    rib->send_to_myself(std::move(sm), &lfl);
}

int
FullyReplicatedLFDB::rib_handler(const CDAPMessage *rm, NeighFlow *nf)
{
    const char *objbuf;
    size_t objlen;
    bool add_f = true;

    if (rm->op_code != gpb::M_CREATE && rm->op_code != gpb::M_DELETE) {
        UPE(rib->uipcp, "M_CREATE or M_DELETE expected\n");
        return 0;
    }

    if (rm->op_code == gpb::M_DELETE) {
        add_f = false;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(rib->uipcp, "M_START does not contain a nested message\n");
        abort();
        return 0;
    }

    LowerFlowList lfl(objbuf, objlen);
    LowerFlowList prop_lfl;
    bool modified = false;

    for (const LowerFlow &f : lfl.flows) {
        if (add_f) {
            if (add(f)) {
                modified = true;
                prop_lfl.flows.push_back(f);
            }

        } else {
            if (del(f.local_node, f.remote_node)) {
                modified = true;
                prop_lfl.flows.push_back(f);
            }
        }
    }

    if (modified) {
        /* Send the received lower flows to the other neighbors. */
        rib->neighs_sync_obj_excluding(nf ? nf->neigh : nullptr, add_f,
                                       obj_class::lfdb, obj_name::lfdb,
                                       &prop_lfl);

        /* Update the routing table. */
        re.update_kernel_routing(rib->myname);
    }

    return 0;
}

void
FullyReplicatedLFDB::update_routing()
{
    /* Update the routing table. */
    re.update_kernel_routing(rib->myname);
}

int
FullyReplicatedLFDB::flow_state_update(struct rl_kmsg_flow_state *upd)
{
    UPD(rib->uipcp, "Flow %u goes %s\n", upd->local_port,
        upd->flow_state == RL_FLOW_STATE_UP ? "up" : "down");

    re.flow_state_update(upd);

    return 0;
}

void
FullyReplicatedLFDB::dump(std::stringstream &ss) const
{
    ss << "Lower Flow Database:" << endl;
    for (const auto &kvi : db) {
        for (const auto &kvj : kvi.second) {
            const LowerFlow &flow = kvj.second;

            ss << "    Local: " << flow.local_node
               << ", Remote: " << flow.remote_node << ", Cost: " << flow.cost
               << ", Seqnum: " << flow.seqnum << ", State: " << flow.state
               << ", Age: " << flow.age << endl;
        }
    }

    ss << endl;
}

void
FullyReplicatedLFDB::dump_routing(std::stringstream &ss) const
{
    re.dump(ss);
}

int
FullyReplicatedLFDB::sync_neigh(NeighFlow *nf, unsigned int limit) const
{
    LowerFlowList lfl;
    int ret = 0;

    if (db.size() > 0) {
        auto it = db.begin();
        auto jt = it->second.begin();
        for (;;) {
            if (jt == it->second.end()) {
                if (++it != db.end()) {
                    jt = it->second.begin();
                }
            }

            if (lfl.flows.size() >= limit || it == db.end()) {
                ret |= nf->neigh->neigh_sync_obj(nf, true, obj_class::lfdb,
                                                 obj_name::lfdb, &lfl);
                lfl.flows.clear();
                if (it == db.end()) {
                    break;
                }
            }

            lfl.flows.push_back(jt->second);
            jt++;
        }
    }

    return ret;
}

int
FullyReplicatedLFDB::neighs_refresh(size_t limit)
{
    unordered_map<NodeId, LowerFlow>::iterator jt;
    int ret = 0;

    if (db.size() == 0) {
        /* Still not enrolled to anyone, nothing to do. */
        return 0;
    }

    /* Fetch the map containing all the LFDB entries with the local
     * address corresponding to me. */
    auto it = db.find(rib->myname);
    assert(it != db.end());

    for (auto jt = it->second.begin(); jt != it->second.end();) {
        LowerFlowList lfl;

        while (lfl.flows.size() < limit && jt != it->second.end()) {
            jt->second.seqnum++;
            lfl.flows.push_back(jt->second);
            jt++;
        }
        ret |= rib->neighs_sync_obj_all(true, obj_class::lfdb, obj_name::lfdb,
                                        &lfl);
    }

    return ret;
}

void
uipcp_rib::age_incr_tmr_restart()
{
    age_incr_timer = make_unique<TimeoutEvent>(
        get_param_value<int>("routing", "age-incr-intval") * 1000, uipcp, this,
        [](struct uipcp *uipcp, void *arg) {
            struct uipcp_rib *rib = (struct uipcp_rib *)arg;
            rib->age_incr_timer->fired();
            rib->lfdb->age_incr();
        });
}

void
FullyReplicatedLFDB::age_incr()
{
    std::lock_guard<std::mutex> guard(rib->mutex);
    bool discarded = false;

    for (auto &kvi : db) {
        list<unordered_map<NodeId, LowerFlow>::iterator> discard_list;

        if (kvi.first == rib->myname) {
            /* Don't age local entries, we pretend they
             * are always refreshed. */
            continue;
        }

        unsigned int age_inc_intval =
            rib->get_param_value<int>("routing", "age-incr-intval");
        unsigned int age_max = rib->get_param_value<int>("routing", "age-max");
        for (auto jt = kvi.second.begin(); jt != kvi.second.end(); jt++) {
            jt->second.age += age_inc_intval;

            if (jt->second.age > age_max) {
                /* Insert this into the list of entries to be discarded. */
                discard_list.push_back(jt);
                discarded = true;
            }
        }

        for (const auto &dit : discard_list) {
            UPI(rib->uipcp, "Discarded lower-flow %s\n",
                static_cast<string>(dit->second).c_str());
            kvi.second.erase(dit);
        }
    }

    if (discarded) {
        /* Update the routing table. */
        re.update_kernel_routing(rib->myname);
    }

    /* Reschedule */
    rib->age_incr_tmr_restart();
}

void
RoutingEngine::compute_shortest_paths(
    const NodeId &source_addr,
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
    info[source_addr].dist = 0;

    for (;;) {
        NodeId min_addr;
        unsigned int min_dist = UINT_MAX;

        /* Select the closest node from the ones in the frontier. */
        for (auto &kvi : info) {
            if (!kvi.second.visited && kvi.second.dist < min_dist) {
                min_addr = kvi.first;
                min_dist = kvi.second.dist;
            }
        }

        if (min_dist == UINT_MAX) {
            break;
        }

        assert(min_addr.size() > 0);

        PV_S("Selecting node %s\n", min_addr.c_str());

        if (!graph.count(min_addr)) {
            continue; /* nothing to do */
        }

        const list<Edge> &edges = graph.at(min_addr);
        Info &info_min          = info[min_addr];

        info_min.visited = true;

        for (const Edge &edge : edges) {
            Info &info_to = info[edge.to];

            if (info_to.dist > info_min.dist + edge.cost) {
                info_to.dist = info_min.dist + edge.cost;
                info_to.nhop =
                    (min_addr == source_addr) ? edge.to : info_min.nhop;
            }
        }
    }

    PV_S("Dijkstra result:\n");
    for (const auto &kvi : info) {
        PV_S("    Node: %s, Dist: %u, Visited %u\n", kvi.first.c_str(),
             kvi.second.dist, (kvi.second.visited));
    }
}

int
RoutingEngine::compute_next_hops(const NodeId &local_node)
{
    std::unordered_map<NodeId, std::unordered_map<NodeId, Info>> neigh_infos;
    std::unordered_map<NodeId, std::list<Edge>> graph;
    std::unordered_map<NodeId, Info> info;

    /* Clean up state left from the previous run. */
    next_hops.clear();

    FullyReplicatedLFDB *lfdb =
        dynamic_cast<FullyReplicatedLFDB *>(rib->lfdb.get());

    /* Build the graph from the Lower Flow Database. */
    graph[local_node] = list<Edge>();
    for (const auto &kvi : lfdb->db) {
        for (const auto &kvj : kvi.second) {
            const LowerFlow *revlf;

            revlf =
                rib->lfdb->find(kvj.second.local_node, kvj.second.remote_node);

            if (revlf == nullptr || revlf->cost != kvj.second.cost) {
                /* Something is wrong, this could be malicious or erroneous. */
                continue;
            }

            graph[kvj.second.local_node].emplace_back(kvj.second.remote_node,
                                                      kvj.second.cost);
            if (!graph.count(kvj.second.remote_node)) {
                /* Make sure graph contains all the nodes, even if with
                 * empty lists. */
                graph[kvj.second.remote_node] = list<Edge>();
            }
        }
    }

    PV_S("Graph [%lu nodes]:\n", lfdb->db.size());
    for (const auto &kvg : graph) {
        PV_S("%s: {", kvg.first.c_str());
        for (const Edge &edge : kvg.second) {
            PV_S("(%s, %u), ", edge.to.c_str(), edge.cost);
        }
        PV_S("}\n");
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

    if (rl_verbosity >= RL_VERB_VERY) {
        stringstream ss;

        dump(ss);
        cout << ss.str();
    }

    return 0;
}

void
RoutingEngine::flow_state_update(struct rl_kmsg_flow_state *upd)
{
    /* Update ports_down accordingly. */
    switch (upd->flow_state) {
    case RL_FLOW_STATE_DOWN:
        ports_down.insert(upd->local_port);
        break;
    case RL_FLOW_STATE_UP:
        ports_down.erase(upd->local_port);
        break;
    }

    /* Recompute the forwarding table. */
    compute_fwd_table();
}

int
RoutingEngine::compute_fwd_table()
{
    unordered_map<rlm_addr_t, pair<NodeId, rl_port_t>> next_ports_new_,
        next_ports_new;
    struct uipcp *uipcp = rib->uipcp;
    unordered_map<rl_port_t, int> port_hits;
    rl_port_t dflt_port;
    int dflt_hits = 0;

    /* Compute the forwarding table by translating the next-hop address
     * into a port-id towards the next-hop. */
    for (const auto &kvr : next_hops) {
        for (const NodeId &lfa : kvr.second) {
            auto neigh = rib->neighbors.find(lfa);
            rlm_addr_t dst_addr;
            rl_port_t port_id;

            if (neigh == rib->neighbors.end()) {
                UPE(uipcp, "Could not find neighbor with name %s\n",
                    lfa.c_str());
                continue;
            }

            if (!neigh->second->has_flows()) {
                UPE(uipcp, "N-1 flow towards neigh %s just disappeared\n",
                    lfa.c_str());
                continue;
            }

            /* Take one of the kernel-bound flows towards the neighbor. */
            port_id = neigh->second->flows.begin()->second->port_id;
            if (ports_down.count(port_id)) {
                UPD(uipcp, "Skipping port %u as it is down\n", port_id);
                continue;
            }

            /* Also make sure we know the address for this destination. */
            dst_addr = rib->lookup_node_address(kvr.first);
            if (dst_addr == RL_ADDR_NULL) {
                /* We still miss the address of this destination. */
                UPV(uipcp, "Can't find address for destination %s\n",
                    kvr.first.c_str());
                continue;
            }

            /* We have found a suitable port for the destination, we can
             * stop searching. */
            next_ports_new_[dst_addr] = make_pair(kvr.first, port_id);
            if (++port_hits[port_id] > dflt_hits) {
                dflt_hits = port_hits[port_id];
                dflt_port = port_id;
                dflt_nhop = lfa;
            }
            break;
        }
    }

#if 1 /* Use default forwarding entry. */
    if (dflt_hits) {
        string any = "";

        /* Prune out those entries corresponding to the default port, and
         * replace them with the default entry. */
        for (const auto &kve : next_ports_new_) {
            if (kve.second.second != dflt_port) {
                next_ports_new[kve.first] = kve.second;
            }
        }
        next_ports_new[RL_ADDR_NULL] = make_pair(any, dflt_port);
        next_hops[any]               = list<NodeId>(1, dflt_nhop);
    }
#else /* Avoid using the default forwarding entry. */
    next_ports_new = next_ports_new_;
#endif

    /* Remove old PDUFT entries first. */
    for (const auto &kve : next_ports) {
        rlm_addr_t dst_addr;
        rl_port_t port_id;
        NodeId dst_node;
        int ret;

        auto nf = next_ports_new.find(kve.first);
        if (nf != next_ports_new.end() &&
            kve.second.second == nf->second.second) {
            /* This old entry still exists, nothing to do. */
            continue;
        }

        /* Delete the old one. */
        dst_addr = kve.first;
        dst_node = kve.second.first;
        port_id  = kve.second.second;
        ret      = uipcp_pduft_del(uipcp, uipcp->id, dst_addr, port_id);
        if (ret) {
            UPE(uipcp,
                "Failed to delete PDUFT entry for %s(%lu) "
                "(port=%u) [%s]\n",
                node_id_pretty(dst_node).c_str(), (long unsigned)dst_addr,
                port_id, strerror(errno));
        } else {
            UPD(uipcp, "Delete PDUFT entry for %s(%lu) (port=%u)\n",
                node_id_pretty(dst_node).c_str(), (long unsigned)dst_addr,
                port_id);
        }
    }

    /* Generate new PDUFT entries. */
    for (auto &kve : next_ports_new) {
        rlm_addr_t dst_addr;
        rl_port_t port_id;
        NodeId dst_node;
        int ret;

        auto of = next_ports.find(kve.first);
        if (of != next_ports.end() && of->second.second == kve.second.second) {
            /* This entry is already in place. */
            continue;
        }

        /* Add the new one. */
        dst_addr = kve.first;
        dst_node = kve.second.first;
        port_id  = kve.second.second;
        ret      = uipcp_pduft_set(uipcp, uipcp->id, dst_addr, port_id);
        if (ret) {
            UPE(uipcp,
                "Failed to insert %s(%lu) --> %s (port=%u) PDUFT "
                "entry [%s]\n",
                node_id_pretty(dst_node).c_str(), (long unsigned)dst_addr,
                next_hops[dst_node].front().c_str(), port_id, strerror(errno));
            /* Trigger re insertion next time. */
            kve.second = make_pair(NodeId(), 0);
        } else {
            UPD(uipcp, "Set PDUFT entry %s(%lu) --> %s (port=%u)\n",
                node_id_pretty(dst_node).c_str(), (long unsigned)dst_addr,
                next_hops[dst_node].front().c_str(), port_id);
        }
    }

    next_ports = next_ports_new;

    return 0;
}

void
RoutingEngine::update_kernel_routing(const NodeId &addr)
{
    assert(rib != nullptr);

    UPV(rib->uipcp, "Recomputing routing and forwarding tables\n");

    /* Step 1: Run a shortest path algorithm. This phase produces the
     * 'next_hops' routing table. */
    compute_next_hops(addr);

    /* Step 2: Using the 'next_hops' routing table, compute forwarding table
     * (in userspace) and update the corresponding kernel data structure. */
    compute_fwd_table();
}

void
RoutingEngine::dump(std::stringstream &ss) const
{
    ss << "Routing table for node " << rib->myname << ":" << endl;
    for (const auto &kvr : next_hops) {
        string dst_node = kvr.first;

        if (dst_node.size() && kvr.second.size() == 1 &&
            kvr.second.front() == dflt_nhop) {
            /* Hide this entry, as it is covered by the default one. */
            continue;
        }

        ss << "    Remote: " << node_id_pretty(dst_node) << ", Next hops: ";
        for (const NodeId &lfa : kvr.second) {
            ss << lfa;
        }
        ss << endl;
    }
}

void
uipcp_rib::lfdb_lib_init()
{
    auto builder = [](uipcp_rib *rib) {
        std::string policy_name = rib->policies["routing"];
        struct FullyReplicatedLFDB *lfdbd;

        if (rib->lfdb == nullptr) {
            rib->lfdb = make_unique<FullyReplicatedLFDB>(rib);
        }
        lfdbd = dynamic_cast<FullyReplicatedLFDB *>(rib->lfdb.get());
        assert(lfdbd != nullptr);

        /* Temporary solution to support LFA policies. No pointer switching is
         * carried out. */
        if (policy_name == "link-state") {
            if (lfdbd->re.lfa_enabled) {
                lfdbd->re.lfa_enabled = false;
                UPD(rib->uipcp, "LFA switched off\n");
            }
        } else if (policy_name == "link-state-lfa") {
            if (!lfdbd->re.lfa_enabled) {
                lfdbd->re.lfa_enabled = true;
                UPD(rib->uipcp, "LFA switched on\n");
            }
        } else {
            assert(false);
        }
    };
    available_policies["routing"].insert(PolicyBuilder("link-state", builder));
    available_policies["routing"].insert(
        PolicyBuilder("link-state-lfa", builder));
}
