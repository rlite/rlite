#include <climits>

#include "uipcp-normal.hpp"

using namespace std;


int
uipcp_rib::add_lower_flow(uint64_t local_addr, const Neighbor& neigh)
{
    LowerFlow lf;
    uint64_t remote_addr = lookup_neighbor_address(neigh.ipcp_name);
    int ret;

    if (remote_addr == 0) {
        PE("Cannot find address for neighbor %s\n",
            static_cast<string>(neigh.ipcp_name).c_str());
        return -1;
    }

    /* Insert the lower flow in the database. */
    lf.local_addr = local_addr;
    lf.remote_addr = remote_addr;
    lf.cost = 1;
    lf.seqnum = 1;
    lf.state = true;
    lf.age = 0;
    lfdb[static_cast<string>(lf)] = lf;

    LowerFlowList lfl;

    /* Send our lower flow database to the neighbor. */
    for (map<string, LowerFlow>::iterator mit = lfdb.begin();
                                        mit != lfdb.end(); mit++) {
        lfl.flows.push_back(mit->second);
    }
    ret = neigh.remote_sync(true, obj_class::lfdb,
                            obj_name::lfdb, &lfl);

    /* Send the new lower flow to the other neighbors. */
    lfl.flows.clear();
    lfl.flows.push_back(lf);
    ret |= remote_sync_excluding(&neigh, true, obj_class::lfdb,
                                 obj_name::lfdb, &lfl);

    /* Update the routing table. */
    spe.run(ipcp_info()->ipcp_addr, lfdb);
    pduft_sync();

    return ret;
}

int
uipcp_rib::lfdb_handler(const CDAPMessage *rm, Neighbor *neigh)
{
    struct rlite_ipcp *ipcp;
    const char *objbuf;
    size_t objlen;
    bool add = true;

    if (rm->op_code != gpb::M_CREATE && rm->op_code != gpb::M_DELETE) {
        PE("M_CREATE or M_DELETE expected\n");
        return 0;
    }

    if (rm->op_code == gpb::M_DELETE) {
        add = false;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_START does not contain a nested message\n");
        abort();
        return 0;
    }

    ipcp = ipcp_info();

    LowerFlowList lfl(objbuf, objlen);
    LowerFlowList prop_lfl;
    RinaName my_name = RinaName(&ipcp->ipcp_name);
    bool modified = false;

    for (list<LowerFlow>::iterator f = lfl.flows.begin();
                                f != lfl.flows.end(); f++) {
        string key = static_cast<string>(*f);
        map< string, LowerFlow >::iterator mit = lfdb.find(key);

        if (add) {
            if (mit == lfdb.end() || f->seqnum > mit->second.seqnum) {
                lfdb[key] = *f;
                modified = true;
                prop_lfl.flows.push_back(*f);
            }
            PD("Lower flow %s added remotely\n", key.c_str());

        } else {
            if (mit == lfdb.end()) {
                PI("Lower flow %s does not exist\n", key.c_str());

            } else {
                lfdb.erase(mit);
                modified = true;
                prop_lfl.flows.push_back(*f);
                PD("Lower flow %s removed remotely\n", key.c_str());
            }

        }
    }

    if (modified) {
        /* Send the received lower flows to the other neighbors. */
        remote_sync_excluding(neigh, add, obj_class::lfdb,
                              obj_name::lfdb, &prop_lfl);

        /* Update the routing table. */
        spe.run(ipcp_info()->ipcp_addr, lfdb);
        pduft_sync();
    }

    return 0;
}

int
SPEngine::run(uint64_t local_addr, const map<string, LowerFlow >& db)
{
    /* Clean up state left from the previous run. */
    next_hops.clear();
    graph.clear();
    info.clear();

    /* Build the graph from the Lower Flow Database. */
    for (map<string, LowerFlow>::const_iterator f = db.begin();
                                            f != db.end(); f++) {
        LowerFlow rev;
        map<string, LowerFlow>::const_iterator revit;

        rev.local_addr = f->second.remote_addr;
        rev.remote_addr = f->second.local_addr;
        revit = db.find(static_cast<string>(rev));

        if (revit == db.end() || revit->second.cost != f->second.cost) {
            /* Something is wrong, this could be malicious or erroneous. */
            continue;
        }

        graph[f->second.local_addr].push_back(Edge(f->second.remote_addr,
                                                   f->second.cost));
    }

#if 1
    PD_S("Graph [%lu]:\n", db.size());
    for (map<uint64_t, list<Edge> >::iterator g = graph.begin();
                                            g != graph.end(); g++) {
        PD_S("%lu: {", (long unsigned)g->first);
        for (list<Edge>::iterator l = g->second.begin();
                                    l != g->second.end(); l++) {
            PD_S("(%lu, %u), ", l->to, l->cost);
        }
        PD_S("}\n");
    }
#endif

    /* Initialize the per-node info map. */
    for (map<uint64_t, list<Edge> >::iterator g = graph.begin();
                                            g != graph.end(); g++) {
        struct Info inf;

        inf.dist = UINT_MAX;
        inf.visited = false;

        info[g->first] = inf;
    }
    info[local_addr].dist = 0;

    for (;;) {
        uint64_t min = UINT_MAX;
        unsigned int min_dist = UINT_MAX;

        /* Select the closest node from the ones in the frontier. */
        for (map<uint64_t, Info>::iterator i = info.begin();
                                        i != info.end(); i++) {
            if (!i->second.visited && i->second.dist < min_dist) {
                min = i->first;
                min_dist = i->second.dist;
            }
        }

        if (min_dist == UINT_MAX) {
            break;
        }

        assert(min != UINT_MAX);

        PD_S("Selecting node %lu\n", (long unsigned)min);

        list<Edge>& edges = graph[min];
        Info& info_min = info[min];

        info_min.visited = true;

        for (list<Edge>::iterator edge = edges.begin();
                                edge != edges.end(); edge++) {
            Info& info_to = info[edge->to];

            if (info_to.dist > info_min.dist + edge->cost) {
                info_to.dist = info_min.dist + edge->cost;
                next_hops[edge->to] = (min == local_addr) ? edge->to :
                                                    next_hops[min];
            }
        }
    }

    PD_S("Dijkstra result:\n");
    for (map<uint64_t, Info>::iterator i = info.begin();
                                    i != info.end(); i++) {
        PD_S("    Address: %lu, Dist: %u, Visited %u\n",
                (long unsigned)i->first, i->second.dist,
                (i->second.visited));
    }

    PD_S("Routing table:\n");
    for (map<uint64_t, uint64_t>::iterator h = next_hops.begin();
                                        h != next_hops.end(); h++) {
        PD_S("    Address: %lu, Next hop: %lu\n",
             (long unsigned)h->first, (long unsigned)h->second);
    }

    return 0;
}

int
uipcp_rib::pduft_sync()
{
    map<uint64_t, unsigned int> next_hop_to_port_id;

    /* Flush previous entries. */
    uipcp_pduft_flush(uipcp, uipcp->ipcp_id);

    /* Precompute the port-ids corresponding to all the possible
     * next-hops. */
    for (map<uint64_t, uint64_t>::iterator r = spe.next_hops.begin();
                                        r !=  spe.next_hops.end(); r++) {
        map<string, Neighbor>::iterator neigh;
        string neigh_name;

        if (next_hop_to_port_id.count(r->second)) {
            continue;
        }

        neigh_name = static_cast<string>(
                                lookup_neighbor_by_address(r->second));
        if (neigh_name == string()) {
            PE("Could not find neighbor with address %lu\n",
                    (long unsigned)r->second);
            continue;
        }

        neigh = neighbors.find(neigh_name);

        if (neigh == neighbors.end()) {
            PE("Could not find neighbor with name %s\n",
                    neigh_name.c_str());
            continue;
        }

        next_hop_to_port_id[r->second] = neigh->second.port_id;
    }

    /* Generate PDUFT entries. */
    for (map<uint64_t, uint64_t>::iterator r = spe.next_hops.begin();
                                        r !=  spe.next_hops.end(); r++) {
            unsigned int port_id = next_hop_to_port_id[r->second];
            int ret = uipcp_pduft_set(uipcp, uipcp->ipcp_id, r->first,
                                      port_id);
            if (ret) {
                PE("Failed to insert %lu --> %u PDUFT entry\n",
                    (long unsigned)r->first, port_id);
            } else {
                PD("Add PDUFT entry %lu --> %u\n",
                    (long unsigned)r->first, port_id);
            }
    }

    return 0;
}

