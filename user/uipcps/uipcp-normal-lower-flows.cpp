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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <climits>
#include <cerrno>
#include <sstream>
#include <iostream>

#include "uipcp-normal.hpp"

using namespace std;


LowerFlow *
lfdb_default::find(const NodeId& local_node, const NodeId& remote_node)
{
    const LowerFlow *lf = _find(local_node, remote_node);
    return const_cast<LowerFlow *>(lf);
}

const LowerFlow *
lfdb_default::_find(const NodeId& local_node, const NodeId& remote_node) const
{
    map<NodeId, map<NodeId, LowerFlow> >::const_iterator it =
                                            db.find(local_node);
    map<NodeId, LowerFlow>::const_iterator jt;

    if (it == db.end()) {
        return NULL;
    }

    jt = it->second.find(remote_node);

    return jt == it->second.end() ? NULL : &jt->second;
}

/* The add method has overwrite semantic, and possibly resets the age.
 * Returns true if something changed. */
bool
lfdb_default::add(const LowerFlow &lf)
{
    map<NodeId, map<NodeId, LowerFlow> >::iterator it = db.find(lf.local_node);
    string repr = static_cast<string>(lf);
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
    if ((!local_entry && lfz.seqnum > it->second[lfz.remote_node].seqnum)
                || (local_entry && lfz != it->second[lfz.remote_node])) {
        it->second[lfz.remote_node] = lfz; /* Update the entry */
        UPV(rib->uipcp, "Lower flow %s updated\n", repr.c_str());
        return true;
    }

    return false;
}

/* Returns true if something changed. */
bool
lfdb_default::del(const NodeId& local_node, const NodeId& remote_node)
{
    map<NodeId, map<NodeId, LowerFlow> >::iterator it
                                            = db.find(local_node);
    map<NodeId, LowerFlow>::iterator jt;
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
lfdb_default::update_local(const string& node_name)
{
    LowerFlowList lfl;
    LowerFlow lf;
    CDAPMessage *sm;

    if (rib->get_neighbor(node_name, false) == NULL) {
        return; /* Not our neighbor. */
    }

    lf.local_node = rib->myname;
    lf.remote_node = node_name;
    lf.cost = 1;
    lf.seqnum = 1; /* not meaningful */
    lf.state = true;
    lf.age = 0;
    lfl.flows.push_back(lf);

    sm = rl_new(CDAPMessage(), RL_MT_CDAP);
    sm->m_create(gpb::F_NO_FLAGS, obj_class::lfdb, obj_name::lfdb, 0, 0, "");
    rib->send_to_myself(sm, &lfl);
}

int
lfdb_default::rib_handler(const CDAPMessage *rm, NeighFlow *nf)
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

    for (list<LowerFlow>::iterator f = lfl.flows.begin();
                                f != lfl.flows.end(); f++) {
        if (add_f) {
            if (add(*f)) {
                modified = true;
                prop_lfl.flows.push_back(*f);
            }

        } else {
            if (del(f->local_node, f->remote_node)) {
                modified = true;
                prop_lfl.flows.push_back(*f);
            }
        }
    }

    if (modified) {
        /* Send the received lower flows to the other neighbors. */
        rib->neighs_sync_obj_excluding(nf ? nf->neigh : NULL, add_f, obj_class::lfdb,
                                  obj_name::lfdb, &prop_lfl);

        /* Update the routing table. */
        re.update_kernel_routing(rib->myname);
    }

    return 0;
}

void
lfdb_default::update_routing()
{
    /* Update the routing table. */
    re.update_kernel_routing(rib->myname);
}

int
lfdb_default::flow_state_update(struct rl_kmsg_flow_state *upd)
{
    UPD(rib->uipcp, "Flow %u goes %s\n", upd->local_port,
        upd->flow_state == RL_FLOW_STATE_UP ? "up" : "down");

    re.flow_state_update(upd);

    return 0;
}

void
lfdb_default::dump(std::stringstream& ss) const
{
    ss << "Lower Flow Database:" << endl;
    for (map<NodeId, map<NodeId, LowerFlow > >::const_iterator
            it = db.begin(); it != db.end(); it++) {
        for (map<NodeId, LowerFlow>::const_iterator jt = it->second.begin();
                                                jt != it->second.end(); jt++) {
        const LowerFlow& flow = jt->second;

        ss << "    Local: " << flow.local_node << ", Remote: "
            << flow.remote_node << ", Cost: " << flow.cost <<
                ", Seqnum: " << flow.seqnum << ", State: " << flow.state
                    << ", Age: " << flow.age << endl;
        }
    }

    ss << endl;
}

void
lfdb_default::dump_routing(std::stringstream& ss) const
{
    re.dump(ss);
}

int
lfdb_default::sync_neigh(NeighFlow *nf, unsigned int limit) const
{
    int ret = 0;

    map< NodeId, map< NodeId, LowerFlow > >::const_iterator it;
    map< NodeId, LowerFlow >::const_iterator jt;
    LowerFlowList lfl;

    if (db.size() > 0) {
        it = db.begin();
        jt = it->second.begin();
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
            jt ++;
        }
    }

    return ret;
}

int
lfdb_default::neighs_refresh(size_t limit)
{
    map< NodeId, map< NodeId, LowerFlow > >::iterator it;
    map< NodeId, LowerFlow >::iterator jt;
    int ret = 0;

    if (db.size() == 0) {
        /* Still not enrolled to anyone, nothing to do. */
        return 0;
    }

    /* Fetch the map containing all the LFDB entries with the local
     * address corresponding to me. */
    it = db.find(rib->myname);
    assert(it != db.end());

    for (map< NodeId, LowerFlow >::iterator jt = it->second.begin();
                                        jt != it->second.end();) {
        LowerFlowList lfl;

        while (lfl.flows.size() < limit && jt != it->second.end()) {
                jt->second.seqnum ++;
                lfl.flows.push_back(jt->second);
                jt ++;
        }
        ret |= rib->neighs_sync_obj_all(true, obj_class::lfdb,
                                   obj_name::lfdb, &lfl);
    }

    return ret;
}

void
age_incr_cb(struct uipcp *uipcp, void *arg)
{
    struct uipcp_rib *rib = (struct uipcp_rib *)arg;
    ScopeLock lock_(rib->lock);
    bool discarded = false;

    lfdb_default *lfdb = dynamic_cast<lfdb_default*>(rib->lfdb);
    assert(lfdb);

    for (map<NodeId, map< NodeId, LowerFlow > >::iterator it
                = lfdb->db.begin(); it != lfdb->db.end(); it++) {
        list<map<NodeId, LowerFlow >::iterator> discard_list;

        if (it->first == rib->myname) {
            /* Don't age local entries, we pretend they
             * are always refreshed. */
            continue;
        }

        for (map<NodeId, LowerFlow >::iterator jt = it->second.begin();
                                                jt != it->second.end(); jt++) {
            jt->second.age += RL_AGE_INCR_INTERVAL;

            if (jt->second.age > RL_AGE_MAX) {
                /* Insert this into the list of entries to be discarded. */
                discard_list.push_back(jt);
                discarded = true;
            }
        }

        for (list<map<NodeId, LowerFlow >::iterator>::iterator dit
                    = discard_list.begin(); dit != discard_list.end(); dit++) {
            UPI(rib->uipcp, "Discarded lower-flow %s\n",
                            static_cast<string>((*dit)->second).c_str());
            it->second.erase(*dit);
        }
    }

    if (discarded) {
        /* Update the routing table. */
        lfdb->re.update_kernel_routing(rib->myname);
    }

    /* Reschedule */
    rib->age_incr_tmrid = uipcp_loop_schedule(uipcp,
                                        RL_AGE_INCR_INTERVAL * 1000,
                                        age_incr_cb, rib);
}

void
RoutingEngine::compute_shortest_paths(const NodeId& source_addr,
                        const std::map<NodeId, std::list<Edge> >& graph,
                        std::map<NodeId, Info>& info)
{
    /* Initialize the per-node info map. */
    for (map<NodeId, list<Edge> >::const_iterator g = graph.begin();
                                            g != graph.end(); g++) {
        struct Info inf;

        inf.dist = UINT_MAX;
        inf.visited = false;

        info[g->first] = inf;
    }
    info[source_addr].dist = 0;

    for (;;) {
        NodeId min_addr;
        unsigned int min_dist = UINT_MAX;

        /* Select the closest node from the ones in the frontier. */
        for (map<NodeId, Info>::iterator i = info.begin();
                                        i != info.end(); i++) {
            if (!i->second.visited && i->second.dist < min_dist) {
                min_addr = i->first;
                min_dist = i->second.dist;
            }
        }

        if (min_dist == UINT_MAX) {
            break;
        }

        assert(min_addr != string());

        PV_S("Selecting node %s\n", min_addr.c_str());

        if (!graph.count(min_addr)) {
            continue; /* nothing to do */
        }

        const list<Edge>& edges = graph.at(min_addr);
        Info& info_min = info[min_addr];

        info_min.visited = true;

        for (list<Edge>::const_iterator edge = edges.begin();
                                edge != edges.end(); edge++) {
            Info& info_to = info[edge->to];

            if (info_to.dist > info_min.dist + edge->cost) {
                info_to.dist = info_min.dist + edge->cost;
                info_to.nhop = (min_addr == source_addr) ? edge->to :
                                                        info_min.nhop;
            }
        }
    }

    PV_S("Dijkstra result:\n");
    for (map<NodeId, Info>::iterator i = info.begin();
                                    i != info.end(); i++) {
        PV_S("    Node: %s, Dist: %u, Visited %u\n",
                 i->first.c_str(), i->second.dist,
                (i->second.visited));
    }
}

int
RoutingEngine::compute_next_hops(const NodeId& local_node)
{
    std::map<NodeId, std::map<NodeId, Info> > neigh_infos;
    std::map<NodeId, std::list<Edge> > graph;
    std::map<NodeId, Info> info;

    /* Clean up state left from the previous run. */
    next_hops.clear();

    lfdb_default *lfdb = dynamic_cast<lfdb_default*>(rib->lfdb);

    /* Build the graph from the Lower Flow Database. */
    graph[local_node] = list<Edge>();
    for (map<NodeId, map<NodeId, LowerFlow > >::const_iterator it
                = lfdb->db.begin(); it != lfdb->db.end(); it++) {
        for (map<NodeId, LowerFlow>::const_iterator jt
                    = it->second.begin(); jt != it->second.end(); jt++) {
            const LowerFlow *revlf;

            revlf = rib->lfdb->find(jt->second.local_node,
                                   jt->second.remote_node);

            if (revlf == NULL || revlf->cost != jt->second.cost) {
                /* Something is wrong, this could be malicious or erroneous. */
                continue;
            }

            graph[jt->second.local_node].push_back(Edge(jt->second.remote_node,
                        jt->second.cost));
            if (!graph.count(jt->second.remote_node)) {
                /* Make sure graph contains all the nodes, even if with
                 * empty lists. */
                graph[jt->second.remote_node] = list<Edge>();
            }
        }
    }

    PV_S("Graph [%lu nodes]:\n", lfdb->db.size());
    for (map<NodeId, list<Edge> >::iterator g = graph.begin();
                                            g != graph.end(); g++) {
        PV_S("%s: {", g->first.c_str());
        for (list<Edge>::iterator l = g->second.begin();
                                    l != g->second.end(); l++) {
            PV_S("(%s, %u), ", l->to.c_str(), l->cost);
        }
        PV_S("}\n");
    }

    /* Compute shortest paths rooted at the local node, and use the
     * result to fill in the next_hops routing table. */
    compute_shortest_paths(local_node, graph, info);
    for (std::map<NodeId, Info>::iterator i = info.begin();
                                        i != info.end(); i++) {
        if (i->first == local_node || !i->second.visited) {
            /* I don't need a next hop for myself. */
            continue;
        }
        next_hops[i->first].push_back(i->second.nhop);
    }

    if (lfa_enabled) {
        /* Compute the shortest paths rooted at each neighbor of the local
         * node, storing the results into neigh_infos. */
        for (list<Edge>::iterator l = graph[local_node].begin();
                                    l != graph[local_node].end(); l++) {
            compute_shortest_paths(l->to, graph, neigh_infos[l->to]);
        }

        /* For each node V other than the local node ... */
        for (map<NodeId, list<Edge> >::iterator v = graph.begin();
                                                v != graph.end(); v++) {
            if (v->first == local_node) {
                continue;
            }

            /* For each neighbor U of the local node, excluding U ... */
            for (std::map<NodeId, std::map<NodeId, Info> >::iterator
                    u = neigh_infos.begin(); u != neigh_infos.end(); u++) {
                if (u->first == v->first) {
                    continue;
                }

                /* dist(U, V) < dist(U, local) + dist(local, V) */
                if (neigh_infos[u->first][v->first].dist <
                            neigh_infos[u->first][local_node].dist +
                                    info[v->first].dist) {
                    bool dupl = false;

                    for (list<NodeId>::iterator
                            lfa = next_hops[v->first].begin();
                                lfa != next_hops[v->first].end(); lfa++) {
                        if (*lfa == u->first) {
                            dupl = true;
                            break;
                        }
                    }

                    if (!dupl) {
                        next_hops[v->first].push_back(u->first);
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
    map<rlm_addr_t, pair<NodeId, rl_port_t> > next_ports_new_, next_ports_new;
    struct uipcp *uipcp = rib->uipcp;
    map<rl_port_t, int> port_hits;
    rl_port_t dflt_port;
    int dflt_hits = 0;

    /* Compute the forwarding table by translating the next-hop address
     * into a port-id towards the next-hop. */
    for (map<NodeId, list<NodeId> >::iterator r = next_hops.begin();
                                        r !=  next_hops.end(); r++) {
        for (list<NodeId>::iterator lfa = r->second.begin();
                                        lfa != r->second.end(); lfa++) {
            map<string, Neighbor*>::iterator neigh;
            rlm_addr_t dst_addr;
            rl_port_t port_id;

            neigh = rib->neighbors.find(*lfa);
            if (neigh == rib->neighbors.end()) {
                UPE(uipcp, "Could not find neighbor with name %s\n",
                           lfa->c_str());
                continue;
            }

            if (!neigh->second->has_flows()) {
                UPE(uipcp, "N-1 flow towards neigh %s just disappeared\n",
                           lfa->c_str());
                continue;
            }

            /* Take one of the kernel-bound flows towards the neighbor. */
            port_id = neigh->second->flows.begin()->second->port_id;
            if (ports_down.count(port_id)) {
                UPD(uipcp, "Skipping port %u as it is down\n", port_id);
                continue;
            }

            /* Also make sure we know the address for this destination. */
            dst_addr = rib->lookup_node_address(r->first);
            if (dst_addr == RL_ADDR_NULL) {
                /* We still miss the address of this destination. */
                UPV(uipcp, "Can't find address for destination %s\n",
                            r->first.c_str());
                continue;
            }

            /* We have found a suitable port for the destination, we can
             * stop searching. */
            next_ports_new_[dst_addr] = make_pair(r->first, port_id);
            if (++ port_hits[port_id] > dflt_hits) {
                dflt_hits = port_hits[port_id];
                dflt_port = port_id;
                dflt_nhop = *lfa;
            }
            break;
        }
    }

#if 1  /* Use default forwarding entry. */
    if (dflt_hits) {
        string any = "";

        /* Prune out those entries corresponding to the default port, and
         * replace them with the default entry. */
        for (map<rlm_addr_t, pair<NodeId, rl_port_t> >::iterator f =
                    next_ports_new_.begin(); f != next_ports_new_.end(); f++) {
            if (f->second.second != dflt_port) {
                next_ports_new[f->first] = f->second;
            }
        }
        next_ports_new[RL_ADDR_NULL] = make_pair(any, dflt_port);
        next_hops[any] = list<NodeId>(1, dflt_nhop);
    }
#else /* Avoid using the default forwarding entry. */
    next_ports_new = next_ports_new_;
#endif

    /* Remove old PDUFT entries first. */
    for (map<rlm_addr_t, pair<NodeId, rl_port_t> >::iterator f =
                next_ports.begin(); f != next_ports.end(); f++) {
            map<rlm_addr_t, pair<NodeId, rl_port_t> >::const_iterator nf;
            rlm_addr_t dst_addr;
            rl_port_t port_id;
            NodeId dst_node;
            int ret;

            nf = next_ports_new.find(f->first);
            if (nf != next_ports_new.end() &&
                            f->second.second == nf->second.second) {
                /* This old entry still exists, nothing to do. */
                continue;
            }

            /* Delete the old one. */
            dst_addr = f->first;
            dst_node = f->second.first;
            port_id = f->second.second;
            ret = uipcp_pduft_del(uipcp, uipcp->id, dst_addr, port_id);
            if (ret) {
                UPE(uipcp, "Failed to delete PDUFT entry for %s(%lu) "
                           "(port=%u) [%s]\n",
                           node_id_pretty(dst_node).c_str(),
                           (long unsigned)dst_addr, port_id, strerror(errno));
            } else {
                UPD(uipcp, "Delete PDUFT entry for %s(%lu) (port=%u)\n",
                           node_id_pretty(dst_node).c_str(),
                           (long unsigned)dst_addr, port_id);
            }
    }

    /* Generate new PDUFT entries. */
    for (map<rlm_addr_t, pair<NodeId, rl_port_t> >::iterator f =
                next_ports_new.begin(); f != next_ports_new.end(); f++) {
            map<rlm_addr_t, pair<NodeId, rl_port_t> >::const_iterator of;
            rlm_addr_t dst_addr;
            rl_port_t port_id;
            NodeId dst_node;
            int ret;

            of = next_ports.find(f->first);
            if (of != next_ports.end() &&
                            of->second.second == f->second.second) {
                /* This entry is already in place. */
                continue;
            }

            /* Add the new one. */
            dst_addr = f->first;
            dst_node = f->second.first;
            port_id = f->second.second;
            ret = uipcp_pduft_set(uipcp, uipcp->id, dst_addr, port_id);
            if (ret) {
                UPE(uipcp, "Failed to insert %s(%lu) --> %s (port=%u) PDUFT "
                           "entry [%s]\n",
                           node_id_pretty(dst_node).c_str(), (long unsigned)dst_addr,
                           next_hops[dst_node].front().c_str(), port_id, strerror(errno));
                /* Trigger re insertion next time. */
                f->second = make_pair(NodeId(), 0);
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
RoutingEngine::update_kernel_routing(const NodeId& addr)
{
    assert(rib != NULL);

    UPV(rib->uipcp, "Recomputing routing and forwarding tables\n");

    /* Step 1: Run a shortest path algorithm. This phase produces the
     * 'next_hops' routing table. */
    compute_next_hops(addr);

    /* Step 2: Using the 'next_hops' routing table, compute forwarding table
     * (in userspace) and update the corresponding kernel data structure. */
    compute_fwd_table();
}

void
RoutingEngine::dump(std::stringstream& ss) const
{
    ss << "Routing table for node " << rib->myname << ":" << endl;
    for (map<NodeId, list<NodeId> >::const_iterator
                h = next_hops.begin(); h != next_hops.end(); h++) {
        string dst_node = h->first;

        if (dst_node.size() && h->second.size() == 1 &&
                            h->second.front() == dflt_nhop) {
            /* Hide this entry, as it is covered by the default one. */
            continue;
        }

        ss << "    Remote: " << node_id_pretty(dst_node) << ", Next hops: ";
        for (list<NodeId>::const_iterator lfa = h->second.begin();
                                lfa != h->second.end(); lfa ++) {
            ss << *lfa;
        }
        ss << endl;
    }
}
