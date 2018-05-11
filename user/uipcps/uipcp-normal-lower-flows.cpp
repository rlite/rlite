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
#include <functional>

#include "uipcp-normal.hpp"

using namespace std;

namespace Uipcps {

using NodeId = std::string;

/* Helper for pretty printing of default route. */
static inline std::string
node_id_pretty(const NodeId &node)
{
    if (node == std::string()) {
        return std::string("any");
    }
    return node;
}

static std::string
to_string(const gpb::LowerFlow &lf)
{
    std::stringstream ss;
    ss << "(" << lf.local_node() << "," << lf.remote_node() << ")";
    return ss.str();
}

static bool
operator==(const gpb::LowerFlow &a, const gpb::LowerFlow &o)
{
    /* Don't use seqnum and age for the comparison. */
    return a.local_node() == o.local_node() &&
           a.remote_node() == o.remote_node() && a.cost() == o.cost();
}

/* Simple class that wraps a Lower Flow database. Used as a component within
 * the other classes. */
struct LFDB {
    /* Lower Flow Database. */
    std::unordered_map<NodeId, std::unordered_map<NodeId, gpb::LowerFlow>> db;

    const gpb::LowerFlow *find(const NodeId &local_node,
                               const NodeId &remote_node) const
    {
        return _find(local_node, remote_node);
    };
    gpb::LowerFlow *find(const NodeId &local_node, const NodeId &remote_node);
    const gpb::LowerFlow *_find(const NodeId &local_node,
                                const NodeId &remote_node) const;
};

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
    unordered_map<NodeId, gpb::LowerFlow>::const_iterator jt;

    if (it == db.end()) {
        return nullptr;
    }

    jt = it->second.find(remote_node);

    return jt == it->second.end() ? nullptr : &jt->second;
}

/* Routing engine able to run the Dijkstra algorithm and compute kernel
 * forwarding tables, using the information contained into an LFDB instance.
 * This class is used as a component for the main Routing classes. */
class RoutingEngine {
public:
    RL_NODEFAULT_NONCOPIABLE(RoutingEngine);
    RoutingEngine(UipcpRib *rib, LFDB *lfdb, bool lfa)
        : rib(rib),
          lfdb(lfdb),
          lfa_enabled(lfa),
          last_run(std::chrono::system_clock::now())
    {
    }

    /* Recompute routing and forwarding table and possibly
     * update kernel forwarding data structures. */
    void update_kernel_routing(const NodeId &);

    void flow_state_update(struct rl_kmsg_flow_state *upd);

    /* Dump the routing table. */
    void dump(std::stringstream &ss) const;

    /* Used by the routing class to ask the RoutingEngine to actually recompute
     * the routing table. */
    void schedule_recomputation() { recompute = true; }

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

public:
    /* Step 3. Forwarding table computation and kernel update. */
    int compute_fwd_table();

    /* The routing table computed by compute_next_hops(), or statically
     * updated. */
    std::unordered_map<NodeId, std::list<NodeId>> next_hops;
    NodeId dflt_nhop;

private:
    /* The forwarding table computed by compute_fwd_table().
     * It maps a NodeId --> (dst_addr, local_port). */
    std::unordered_map<rlm_addr_t, std::pair<NodeId, rl_port_t>> next_ports;

    /* Set of ports that are currently down. */
    std::unordered_set<rl_port_t> ports_down;

    /* Should update_kernel_routing() really run the graph algorithms and
     * udpate the kernel. */
    bool recompute = true;

    /* Backpointer. */
    UipcpRib *rib;

    /* The Lower Flows database. */
    LFDB *lfdb;

    /* Is Loop Free Alternate algorithm enabled ? */
    bool lfa_enabled;

    /* Last time we ran the routing algorithm. */
    std::chrono::system_clock::time_point last_run;

    /* Minimum size of the LFDB after which we start to rate limit routing
     * computations. */
    size_t coalesce_size_threshold = 50;

    /* Minimum number of seconds that must elapse between two consecutive
     * routing table computations, if rate limiting is active. */
    Secs coalesce_period = Secs(5);

    /* Timer to provide an upper bound for the coalescing period. */
    std::unique_ptr<TimeoutEvent> coalesce_timer;
};

class FullyReplicatedLFDB : public Routing {
    /* Lower Flow Database. */
    LFDB lfdb;

    /* Routing engine. */
    RoutingEngine re;

public:
    RL_NODEFAULT_NONCOPIABLE(FullyReplicatedLFDB);
    FullyReplicatedLFDB(UipcpRib *rib, bool lfa)
        : Routing(rib), re(rib, &lfdb, lfa)
    {
    }
    ~FullyReplicatedLFDB() {}

    void dump(std::stringstream &ss) const override;
    void dump_routing(std::stringstream &ss) const override { re.dump(ss); }

    bool add(const gpb::LowerFlow &lf);
    bool del(const NodeId &local_node, const NodeId &remote_node);
    void update_local(const std::string &neigh_name) override;
    void update_kernel(bool force = true) override;
    int flow_state_update(struct rl_kmsg_flow_state *upd) override;
    void neigh_disconnected(const std::string &neigh_name) override;

    int rib_handler(const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
                    std::shared_ptr<Neighbor> const &neigh,
                    rlm_addr_t src_addr) override;

    int sync_neigh(const std::shared_ptr<NeighFlow> &nf,
                   unsigned int limit) const override;
    int neighs_refresh(size_t limit) override;
    void age_incr() override;

    /* Time interval (in seconds) between two consecutive increments
     * of the age of LFDB entries. */
    static constexpr int kAgeIncrIntvalSecs = 10;

    /* Max age (in seconds) for an LFDB entry not to be discarded. */
    static constexpr int kAgeMaxSecs = 900;
};

/* The add method has overwrite semantic, and possibly resets the age.
 * Returns true if something changed. */
bool
FullyReplicatedLFDB::add(const gpb::LowerFlow &lf)
{
    auto it            = lfdb.db.find(lf.local_node());
    string repr        = to_string(lf);
    gpb::LowerFlow lfz = lf;

    lfz.set_age(0);

    if (it == lfdb.db.end() || it->second.count(lf.remote_node()) == 0) {
        /* Not there, we should add the entry. */
        if (lf.local_node() == rib->myname &&
            rib->get_neighbor(lf.remote_node(), /*create=*/false) == nullptr) {
            /* Someone is telling us to add an entry where we are the local
             * node, but there is no neighbor. Discard the update. */
            UPD(rib->uipcp, "Lower flow %s not added (no such neighbor)\n",
                repr.c_str());
            return false;
        }
        lfdb.db[lf.local_node()][lf.remote_node()] = lfz;
        re.schedule_recomputation();
        UPD(rib->uipcp, "Lower flow %s added\n", repr.c_str());
        return true;
    }

    /* Entry is already there. Update if needed (this expression
     * was obtained by means of a Karnaugh map on three variables:
     * local, newer, equal). */
    bool local_entry = (lfz.local_node() == rib->myname);
    bool newer       = lfz.seqnum() > it->second[lfz.remote_node()].seqnum();
    bool equal       = lfz == it->second[lfz.remote_node()];
    if ((!local_entry && newer) || (local_entry && !equal)) {
        it->second[lfz.remote_node()] = std::move(lfz); /* Update the entry */
        if (equal) {
            /* The affected flow entry is just refreshed, but it did not
             * change. No recomputation is needed. */
            UPV(rib->uipcp, "Lower flow %s refreshed\n", repr.c_str());
        } else {
            /* The affected flow entry changed, so we ask the RoutingEngine
             * for recomputation. */
            UPD(rib->uipcp, "Lower flow %s updated\n", repr.c_str());
            re.schedule_recomputation();
        }
        return true;
    }

    return false;
}

/* Returns true if something changed. */
bool
FullyReplicatedLFDB::del(const NodeId &local_node, const NodeId &remote_node)
{
    auto it = lfdb.db.find(local_node);
    unordered_map<NodeId, gpb::LowerFlow>::iterator jt;
    string repr;

    if (it == lfdb.db.end()) {
        return false;
    }

    jt = it->second.find(remote_node);

    if (jt == it->second.end()) {
        return false;
    }
    repr = to_string(jt->second);

    it->second.erase(jt);

    UPD(rib->uipcp, "Lower flow %s removed\n", repr.c_str());

    return true;
}

void
FullyReplicatedLFDB::update_local(const string &node_name)
{
    gpb::LowerFlowList lfl;
    gpb::LowerFlow *lf;
    std::unique_ptr<CDAPMessage> sm;

    if (rib->get_neighbor(node_name, false) == nullptr) {
        return; /* Not our neighbor. */
    }

    lf = lfl.add_flows();
    lf->set_local_node(rib->myname);
    lf->set_remote_node(node_name);
    lf->set_cost(1);
    lf->set_seqnum(1); /* not meaningful */
    lf->set_state(true);
    lf->set_age(0);

    sm = make_unique<CDAPMessage>();
    sm->m_create(ObjClass, TableName);
    rib->send_to_myself(std::move(sm), &lfl);
}

int
FullyReplicatedLFDB::rib_handler(const CDAPMessage *rm,
                                 std::shared_ptr<NeighFlow> const &nf,
                                 std::shared_ptr<Neighbor> const &neigh,
                                 rlm_addr_t src_addr)
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

    gpb::LowerFlowList lfl;
    gpb::LowerFlowList prop_lfl;

    lfl.ParseFromArray(objbuf, objlen);

    for (const gpb::LowerFlow &f : lfl.flows()) {
        if (add_f) {
            if (add(f)) {
                *prop_lfl.add_flows() = f;
            }

        } else {
            if (del(f.local_node(), f.remote_node())) {
                *prop_lfl.add_flows() = f;
            }
        }
    }

    if (prop_lfl.flows_size() > 0) {
        /* Send the received lower flows to the other neighbors. */
        rib->neighs_sync_obj_excluding(neigh, add_f, ObjClass, TableName,
                                       &prop_lfl);

        /* Update the kernel routing table. */
        update_kernel(/*force=*/false);
    }

    return 0;
}

void
FullyReplicatedLFDB::update_kernel(bool force)
{
    /* Update the routing table. */
    if (force) {
        re.schedule_recomputation();
    }
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
    for (const auto &kvi : lfdb.db) {
        for (const auto &kvj : kvi.second) {
            const gpb::LowerFlow &flow = kvj.second;

            ss << "    Local: " << flow.local_node()
               << ", Remote: " << flow.remote_node()
               << ", Cost: " << flow.cost() << ", Seqnum: " << flow.seqnum()
               << ", State: " << flow.state() << ", Age: " << flow.age()
               << endl;
        }
    }

    ss << endl;
}

int
FullyReplicatedLFDB::sync_neigh(const std::shared_ptr<NeighFlow> &nf,
                                unsigned int limit) const
{
    gpb::LowerFlowList lfl;
    auto func =
        std::bind(&NeighFlow::sync_obj, nf, true, ObjClass, TableName, &lfl);
    int ret = 0;

    for (const auto &kvi : lfdb.db) {
        for (const auto &kvj : kvi.second) {
            const gpb::LowerFlow &flow = kvj.second;

            *lfl.add_flows() = flow;
            if (lfl.flows_size() >= static_cast<int>(limit)) {
                ret |= func();
                lfl = gpb::LowerFlowList();
            }
        }
    }

    if (lfl.flows_size() > 0) {
        ret |= func();
    }

    return ret;
}

int
FullyReplicatedLFDB::neighs_refresh(size_t limit)
{
    unordered_map<NodeId, gpb::LowerFlow>::iterator jt;
    int ret = 0;

    if (lfdb.db.size() == 0) {
        /* Still not enrolled to anyone, nothing to do. */
        return 0;
    }

    /* Fetch the map containing all the LFDB entries with the local
     * address corresponding to me. */
    auto it = lfdb.db.find(rib->myname);
    assert(it != lfdb.db.end());

    auto age_thresh = rib->get_param_value<Msecs>(Routing::Prefix, "age-max");
    age_thresh      = age_thresh * 30 / 100;

    for (auto jt = it->second.begin(); jt != it->second.end();) {
        gpb::LowerFlowList lfl;

        while (lfl.flows_size() < static_cast<int>(limit) &&
               jt != it->second.end()) {
            auto age = Secs(jt->second.age());

            /* Renew the entry by incrementing its sequence number if
             * we reached ~1/3 of the maximum age. */
            if (age >= age_thresh) {
                jt->second.set_seqnum(jt->second.seqnum() + 1);
                jt->second.set_age(0);
            }
            *lfl.add_flows() = jt->second;
            jt++;
        }
        ret |= rib->neighs_sync_obj_all(true, ObjClass, TableName, &lfl);
    }

    return ret;
}

void
UipcpRib::age_incr_tmr_restart()
{
    age_incr_timer = make_unique<TimeoutEvent>(
        get_param_value<Msecs>(Routing::Prefix, "age-incr-intval"), uipcp, this,
        [](struct uipcp *uipcp, void *arg) {
            UipcpRib *rib = (UipcpRib *)arg;
            rib->age_incr_timer->fired();
            rib->routing->age_incr();
        });
}

/* Called from timer context, we need to take the RIB lock. */
void
FullyReplicatedLFDB::age_incr()
{
    std::lock_guard<std::mutex> guard(rib->mutex);
    auto age_inc_intval =
        rib->get_param_value<Msecs>(Routing::Prefix, "age-incr-intval");
    auto age_max = rib->get_param_value<Msecs>(Routing::Prefix, "age-max");
    gpb::LowerFlowList prop_lfl;

    for (auto &kvi : lfdb.db) {
        list<unordered_map<NodeId, gpb::LowerFlow>::iterator> discard_list;

        for (auto jt = kvi.second.begin(); jt != kvi.second.end(); jt++) {
            auto next_age = Secs(jt->second.age());

            next_age += std::chrono::duration_cast<Secs>(age_inc_intval);
            jt->second.set_age(next_age.count());

            if (kvi.first != rib->myname && next_age > age_max) {
                /* Insert this into the list of entries to be discarded. Don't
                 * discard local entries. */
                discard_list.push_back(jt);
            }
        }

        for (const auto &dit : discard_list) {
            UPI(rib->uipcp, "Discarded lower-flow %s (age)\n",
                to_string(dit->second).c_str());
            *prop_lfl.add_flows() = dit->second;
            kvi.second.erase(dit);
        }
    }

    if (prop_lfl.flows_size() > 0) {
        rib->neighs_sync_obj_all(/*create=*/false, ObjClass, TableName,
                                 &prop_lfl);
        /* Update the routing table. */
        update_kernel();
    }

    /* Reschedule */
    rib->age_incr_tmr_restart();
}

void
FullyReplicatedLFDB::neigh_disconnected(const std::string &neigh_name)
{
    gpb::LowerFlowList prop_lfl;

    for (auto &kvi : lfdb.db) {
        list<unordered_map<NodeId, gpb::LowerFlow>::iterator> discard_list;

        for (auto jt = kvi.second.begin(); jt != kvi.second.end(); jt++) {
            if ((kvi.first == rib->myname && jt->first == neigh_name) ||
                (kvi.first == neigh_name && jt->first == rib->myname)) {
                /* Insert this into the list of entries to be discarded. */
                discard_list.push_back(jt);
            }
        }

        for (const auto &dit : discard_list) {
            UPI(rib->uipcp, "Discarded lower-flow %s (neighbor disconnected)\n",
                to_string(dit->second).c_str());
            *prop_lfl.add_flows() = dit->second;
            kvi.second.erase(dit);
        }
    }

    if (prop_lfl.flows_size() > 0) {
        rib->neighs_sync_obj_all(/*create=*/false, ObjClass, TableName,
                                 &prop_lfl);
        /* Update the routing table. */
        update_kernel();
    }
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

    /* Build the graph from the Lower Flow Database. */
    graph[local_node] = list<Edge>();
    for (const auto &kvi : lfdb->db) {
        for (const auto &kvj : kvi.second) {
            const gpb::LowerFlow *revlf;

            revlf =
                lfdb->find(kvj.second.local_node(), kvj.second.remote_node());

            if (revlf == nullptr || revlf->cost() != kvj.second.cost()) {
                /* Something is wrong, this could be malicious or erroneous. */
                continue;
            }

            graph[kvj.second.local_node()].emplace_back(
                kvj.second.remote_node(), kvj.second.cost());
            if (!graph.count(kvj.second.remote_node())) {
                /* Make sure graph contains all the nodes, even if with
                 * empty lists. */
                graph[kvj.second.remote_node()] = list<Edge>();
            }
        }
    }

    PV_S("Graph [%lu nodes]:\n", (long unsigned)lfdb->db.size());
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

    rib->stats.routing_table_compute++;

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
                UPD(uipcp, "Skipping port_id %u as it is down\n", port_id);
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
        ret      = uipcp_pduft_del(uipcp, dst_addr, port_id);
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
        ret      = uipcp_pduft_set(uipcp, dst_addr, port_id);
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
    rib->stats.fwd_table_compute++;

    return 0;
}

void
RoutingEngine::update_kernel_routing(const NodeId &addr)
{
    assert(rib != nullptr);

    if (!recompute) {
        return; /* Nothing to do. */
    }

    auto now = std::chrono::system_clock::now();

    if (lfdb->db.size() > coalesce_size_threshold &&
        (now - last_run) < coalesce_period) {
        /* Postpone this computation, possibly starting the coalesce timer. */
        if (!coalesce_timer) {
            coalesce_timer = make_unique<TimeoutEvent>(
                coalesce_period, rib->uipcp, this,
                [](struct uipcp *uipcp, void *arg) {
                    RoutingEngine *re = (RoutingEngine *)arg;
                    re->coalesce_timer->fired();
                    re->update_kernel_routing(re->rib->myname);
                });
        }
        return;
    }

    if (coalesce_timer) {
        coalesce_timer->clear();
        coalesce_timer = nullptr;
    }
    recompute = false;
    last_run  = now;

    UPD(rib->uipcp, "Recomputing routing and forwarding tables\n");

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
        for (auto lfa = kvr.second.begin();;) {
            ss << *lfa;
            if (++lfa == kvr.second.end()) {
                break;
            }
            ss << " ";
        }
        ss << endl;
    }
}

class StaticRouting : public Routing {
    /* Lower Flow Database. */
    LFDB lfdb;

    /* Routing engine, only used to compute kernel fowarding tables. */
    RoutingEngine re;

public:
    RL_NODEFAULT_NONCOPIABLE(StaticRouting);
    StaticRouting(UipcpRib *_ur) : Routing(_ur), re(_ur, &lfdb, true) {}
    ~StaticRouting() {}

    void dump(std::stringstream &ss) const override { dump_routing(ss); }
    void dump_routing(std::stringstream &ss) const override { re.dump(ss); }
    int route_mod(const struct rl_cmsg_ipcp_route_mod *req) override;
};

int
StaticRouting::route_mod(const struct rl_cmsg_ipcp_route_mod *req)
{
    std::string dest_ipcp;
    std::list<NodeId> next_hops;

    if (!req->dest_name || strlen(req->dest_name) == 0) {
        UPE(rib->uipcp, "No destination IPCP specified\n");
        return -1;
    }

    dest_ipcp = req->dest_name;

    if (req->hdr.msg_type == RLITE_U_IPCP_ROUTE_ADD) {
        if (!req->next_hops || strlen(req->next_hops) == 0) {
            UPE(rib->uipcp, "No next hop specified\n");
            return -1;
        }
        next_hops = strsplit(NodeId(req->next_hops), ',');
        {
            set<NodeId> u(next_hops.begin(), next_hops.end());
            if (u.size() != next_hops.size()) {
                UPE(rib->uipcp, "Next hops list contains duplicates\n");
                return -1;
            }
        }
        re.next_hops[dest_ipcp] = next_hops;
    } else { /* RLITE_U_IPCP_ROUTE_DEL */
        if (!re.next_hops.count(dest_ipcp)) {
            UPE(rib->uipcp, "No route to destination '%s'\n", req->dest_name);
            return -1;
        }
        re.next_hops.erase(dest_ipcp);
    }

    re.compute_fwd_table();

    return 0;
}

void
UipcpRib::routing_lib_init()
{
    std::list<std::pair<std::string, PolicyParam>> link_state_params = {
        {"age-incr-intval",
         PolicyParam(Secs(int(FullyReplicatedLFDB::kAgeIncrIntvalSecs)))},
        {"age-max", PolicyParam(Secs(int(FullyReplicatedLFDB::kAgeMaxSecs)))}};

    available_policies[Routing::Prefix].insert(PolicyBuilder(
        "link-state",
        [](UipcpRib *rib) {
            rib->routing = make_unique<FullyReplicatedLFDB>(rib, false);
        },
        {Routing::TableName}, link_state_params));
    available_policies[Routing::Prefix].insert(PolicyBuilder(
        "link-state-lfa",
        [](UipcpRib *rib) {
            rib->routing = make_unique<FullyReplicatedLFDB>(rib, true);
        },
        {Routing::TableName}, link_state_params));
    available_policies[Routing::Prefix].insert(PolicyBuilder(
        "static",
        [](UipcpRib *rib) { rib->routing = make_unique<StaticRouting>(rib); }));
}

} // namespace Uipcps
