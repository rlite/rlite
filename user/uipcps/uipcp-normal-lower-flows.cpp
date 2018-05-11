/*
 * Routing policies.
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
#include "uipcp-normal-lfdb.hpp"

using namespace std;

namespace rlite {

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

/* Routing engine able to run the Dijkstra algorithm and compute kernel
 * forwarding tables, using the information contained into an LFDB instance.
 * This class is used as a component for the main Routing classes. */
class RoutingEngine : public LFDB {
public:
    RL_NODEFAULT_NONCOPIABLE(RoutingEngine);
    RoutingEngine(UipcpRib *rib, bool lfa_enabled)
        : LFDB(/*lfa_enabled=*/lfa_enabled,
               /*verbose=*/rl_verbosity >= RL_VERB_VERY),
          rib(rib),
          last_run(std::chrono::system_clock::now())
    {
    }

    /* Recompute routing and forwarding table and possibly
     * update kernel forwarding data structures. */
    void update_kernel_routing(const NodeId &);

    void flow_state_update(struct rl_kmsg_flow_state *upd);

    /* Used by the routing class to ask the RoutingEngine to actually recompute
     * the routing table. */
    void schedule_recomputation() { recompute = true; }

    /* Forwarding table computation and kernel update. */
    int compute_fwd_table();

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
                /* This should not happen, because it would mean that we
                 * declared to have a local LFDB entry without a corresponding
                 * local flow. */
                UPE(uipcp, "No flow for next hop %s\n",
                    neigh->second->ipcp_name.c_str());
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
        next_hops[any]               = std::vector<NodeId>(1, dflt_nhop);
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

/* To be called under RIB lock. */
void
RoutingEngine::update_kernel_routing(const NodeId &addr)
{
    assert(rib != nullptr);

    if (!recompute) {
        return; /* Nothing to do. */
    }

    auto now = std::chrono::system_clock::now();

    if (db.size() > coalesce_size_threshold &&
        (now - last_run) < coalesce_period) {
        /* Postpone this computation, possibly starting the coalesce timer. */
        if (!coalesce_timer) {
            coalesce_timer = utils::make_unique<TimeoutEvent>(
                coalesce_period, rib->uipcp, this,
                [](struct uipcp *uipcp, void *arg) {
                    RoutingEngine *re = (RoutingEngine *)arg;
                    std::lock_guard<std::mutex> guard(re->rib->mutex);
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
    rib->stats.routing_table_compute++;

    /* Step 2: Using the 'next_hops' routing table, compute forwarding table
     * (in userspace) and update the corresponding kernel data structure. */
    compute_fwd_table();
}

/* Link state routing, optionally supporting LFA. */
class LinkStateRouting : public Routing {
    /* Routing engine. */
    RoutingEngine re;

    /* Timer ID for age increment of LFDB entries. */
    std::unique_ptr<TimeoutEvent> age_incr_timer;

public:
    RL_NODEFAULT_NONCOPIABLE(LinkStateRouting);
    LinkStateRouting(UipcpRib *rib, bool lfa)
        : Routing(rib), re(rib, /*lfa_enabled=*/lfa)
    {
        age_incr_tmr_restart();
    }
    ~LinkStateRouting() { age_incr_timer.reset(); }

    void dump(std::stringstream &ss) const override { re.dump(ss); }
    void dump_routing(std::stringstream &ss) const override
    {
        re.dump_routing(ss, rib->myname);
    }

    bool add(const gpb::LowerFlow &lf);
    bool del(const NodeId &local_node, const NodeId &remote_node);
    void update_local(const std::string &neigh_name) override;
    void update_kernel(bool force = true) override;
    int flow_state_update(struct rl_kmsg_flow_state *upd) override;
    void neigh_disconnected(const std::string &neigh_name) override;

    int rib_handler(const CDAPMessage *rm, const MsgSrcInfo &src) override;

    int sync_neigh(const std::shared_ptr<NeighFlow> &nf,
                   unsigned int limit) const override;
    int neighs_refresh(size_t limit) override;
    void age_incr();
    void age_incr_tmr_restart();

    /* Time interval (in seconds) between two consecutive increments
     * of the age of LFDB entries. */
    static constexpr int kAgeIncrIntvalSecs = 10;

    /* Max age (in seconds) for an LFDB entry not to be discarded. */
    static constexpr int kAgeMaxSecs = 900;
};

/* The add method has overwrite semantic, and possibly resets the age.
 * Returns true if something changed. */
bool
LinkStateRouting::add(const gpb::LowerFlow &lf)
{
    auto it            = re.db.find(lf.local_node());
    string repr        = to_string(lf);
    gpb::LowerFlow lfz = lf;

    lfz.set_age(0);

    if (it == re.db.end() || it->second.count(lf.remote_node()) == 0) {
        /* Not there, we should add the entry. */
        if (lf.local_node() == rib->myname &&
            rib->get_neighbor(lf.remote_node(), /*create=*/false) == nullptr) {
            /* Someone is telling us to add an entry where we are the local
             * node, but there is no neighbor. Discard the update. */
            UPD(rib->uipcp, "Lower flow %s not added (no such neighbor)\n",
                repr.c_str());
            return false;
        }
        re.db[lf.local_node()][lf.remote_node()] = lfz;
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
LinkStateRouting::del(const NodeId &local_node, const NodeId &remote_node)
{
    auto it = re.db.find(local_node);
    unordered_map<NodeId, gpb::LowerFlow>::iterator jt;
    string repr;

    if (it == re.db.end()) {
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
LinkStateRouting::update_local(const string &node_name)
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

    sm = utils::make_unique<CDAPMessage>();
    sm->m_create(ObjClass, TableName);
    rib->send_to_myself(std::move(sm), &lfl);
}

int
LinkStateRouting::rib_handler(const CDAPMessage *rm, const MsgSrcInfo &src)
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
        rib->neighs_sync_obj_excluding(src.neigh, add_f, ObjClass, TableName,
                                       &prop_lfl);

        /* Update the kernel routing table. */
        update_kernel(/*force=*/false);
    }

    return 0;
}

void
LinkStateRouting::update_kernel(bool force)
{
    /* Update the routing table. */
    if (force) {
        re.schedule_recomputation();
    }
    re.update_kernel_routing(rib->myname);
}

int
LinkStateRouting::flow_state_update(struct rl_kmsg_flow_state *upd)
{
    UPD(rib->uipcp, "Flow %u goes %s\n", upd->local_port,
        upd->flow_state == RL_FLOW_STATE_UP ? "up" : "down");

    re.flow_state_update(upd);

    return 0;
}

int
LinkStateRouting::sync_neigh(const std::shared_ptr<NeighFlow> &nf,
                             unsigned int limit) const
{
    gpb::LowerFlowList lfl;
    auto func =
        std::bind(&NeighFlow::sync_obj, nf, true, ObjClass, TableName, &lfl);
    int ret = 0;

    for (const auto &kvi : re.db) {
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
LinkStateRouting::neighs_refresh(size_t limit)
{
    unordered_map<NodeId, gpb::LowerFlow>::iterator jt;
    int ret = 0;

    if (re.db.size() == 0) {
        /* Still not enrolled to anyone, nothing to do. */
        return 0;
    }

    /* Fetch the map containing all the LFDB entries with the local
     * address corresponding to me. */
    auto it = re.db.find(rib->myname);
    assert(it != re.db.end());

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
LinkStateRouting::age_incr_tmr_restart()
{
    age_incr_timer = utils::make_unique<TimeoutEvent>(
        rib->get_param_value<Msecs>(Routing::Prefix, "age-incr-intval"),
        rib->uipcp, this, [](struct uipcp *uipcp, void *arg) {
            LinkStateRouting *r = (LinkStateRouting *)arg;
            std::lock_guard<std::mutex> guard(r->rib->mutex);
            r->age_incr_timer->fired();
            r->age_incr();
        });
}

/* Called from timer context, under RIB lock. */
void
LinkStateRouting::age_incr()
{
    auto age_inc_intval =
        rib->get_param_value<Msecs>(Routing::Prefix, "age-incr-intval");
    auto age_max = rib->get_param_value<Msecs>(Routing::Prefix, "age-max");
    gpb::LowerFlowList prop_lfl;

    for (auto &kvi : re.db) {
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
    age_incr_tmr_restart();
}

void
LinkStateRouting::neigh_disconnected(const std::string &neigh_name)
{
    gpb::LowerFlowList prop_lfl;

    for (auto &kvi : re.db) {
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

class StaticRouting : public Routing {
    /* Routing engine, only used to compute kernel fowarding tables. */
    RoutingEngine re;

public:
    RL_NODEFAULT_NONCOPIABLE(StaticRouting);
    StaticRouting(UipcpRib *_ur) : Routing(_ur), re(_ur, /*lfa_enabled=*/true)
    {
    }
    ~StaticRouting() {}

    void dump(std::stringstream &ss) const override { re.dump(ss); }
    void dump_routing(std::stringstream &ss) const override
    {
        re.dump_routing(ss, rib->myname);
    }
    int route_mod(const struct rl_cmsg_ipcp_route_mod *req) override;
};

int
StaticRouting::route_mod(const struct rl_cmsg_ipcp_route_mod *req)
{
    std::string dest_ipcp;
    std::vector<NodeId> next_hops;

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
        next_hops = utils::strsplit<std::vector>(NodeId(req->next_hops), ',');
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
    std::vector<std::pair<std::string, PolicyParam>> link_state_params = {
        {"age-incr-intval",
         PolicyParam(Secs(int(LinkStateRouting::kAgeIncrIntvalSecs)))},
        {"age-max", PolicyParam(Secs(int(LinkStateRouting::kAgeMaxSecs)))}};

    available_policies[Routing::Prefix].insert(PolicyBuilder(
        "link-state",
        [](UipcpRib *rib) {
            return utils::make_unique<LinkStateRouting>(rib, false);
        },
        {Routing::TableName}, link_state_params));
    available_policies[Routing::Prefix].insert(PolicyBuilder(
        "link-state-lfa",
        [](UipcpRib *rib) {
            return utils::make_unique<LinkStateRouting>(rib, true);
        },
        {Routing::TableName}, link_state_params));
    available_policies[Routing::Prefix].insert(PolicyBuilder(
        "static",
        [](UipcpRib *rib) { return utils::make_unique<StaticRouting>(rib); }));
}

} // namespace rlite
