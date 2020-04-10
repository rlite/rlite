#include "uipcp-normal.hpp"
#include "uipcp-normal-lfdb.hpp"
#include <vector>

using namespace std;

namespace rlite {

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
          last_run(chrono::system_clock::now())
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
    unordered_map<rlm_addr_t, pair<NodeId, rl_port_t>> next_ports;

    /* Set of ports that are currently down. */
    unordered_set<rl_port_t> ports_down;

    /* Should update_kernel_routing() really run the graph algorithms and
     * udpate the kernel. */
    bool recompute = true;

    /* Backpointer. */
    UipcpRib *rib;

    /* Last time we ran the routing algorithm. */
    chrono::system_clock::time_point last_run;

    /* Minimum size of the LFDB after which we start to rate limit routing
     * computations. */
    size_t coalesce_size_threshold = 50;

    /* Minimum number of seconds that must elapse between two consecutive
     * routing table computations, if rate limiting is active. */
    Secs coalesce_period = Secs(5);

    /* Timer to provide an upper bound for the coalescing period. */
    unique_ptr<TimeoutEvent> coalesce_timer;
};

/* Link state routing, optionally supporting LFA. */
class LinkStateRouting : public Routing {
protected:
    /* Routing engine. */
    RoutingEngine re;

    /* Timer ID for age increment of LFDB entries. */
    unique_ptr<TimeoutEvent> age_incr_timer;

public:
    RL_NODEFAULT_NONCOPIABLE(LinkStateRouting);
    LinkStateRouting(UipcpRib *rib, bool lfa)
        : Routing(rib), re(rib, /*lfa_enabled=*/lfa)
    {
        age_incr_tmr_restart();
    }
    ~LinkStateRouting() { age_incr_timer.reset(); }

    void dump(stringstream &ss) const override { re.dump(ss); }
    void dump_routing(stringstream &ss) const override
    {
        re.dump_routing(ss, rib->myname);
    }

    bool add(const gpb::LowerFlow &lf);
    bool del(const NodeId &local_node, const NodeId &remote_node);
    void update_local(const string &neigh_name) override;
    void update_kernel(bool force = true) override;
    int flow_state_update(struct rl_kmsg_flow_state *upd) override;
    void neigh_disconnected(const string &neigh_name) override;

    int rib_handler(const CDAPMessage *rm, const MsgSrcInfo &src) override;

    int sync_neigh(const shared_ptr<NeighFlow> &nf,
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

class BwResRouting : public LinkStateRouting {
public:
    RL_NODEFAULT_NONCOPIABLE(BwResRouting);
    BwResRouting(UipcpRib *rib, bool lfa) : LinkStateRouting(rib, lfa) {}

    vector<NodeId> find_flow_path(const NodeId &src_node,
                                  const NodeId &dest_node,
                                  const unsigned long req_flow)
    {
        return re.find_flow_path(src_node, dest_node, req_flow);
    }

    void update_local(const string &node_name) override;
    void reserve_flow(const vector<NodeId> path, unsigned long bw);
    void free_flow(const vector<NodeId> path, unsigned long bw);

    int rib_handler(const CDAPMessage *rm, const MsgSrcInfo &src) override;

    static string PerFlowObjClass;
};

} // namespace rlite
