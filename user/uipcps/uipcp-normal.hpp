/*
 * Core implementation of normal uipcps.
 *
 * Copyright (C) 2015-2016 Nextworks
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

#ifndef __UIPCP_RIB_H__
#define __UIPCP_RIB_H__

#include <string>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <ctime>
#include <sstream>
#include <pthread.h>
#include <utility>

#include "rlite/common.h"
#include "rlite/utils.h"
#include "rlite/uipcps-msg.h"
#include "rina/cdap.hpp"
#include "rlite/cpputils.hpp"

#include "uipcp-normal-codecs.hpp"
#include "uipcp-container.h"

namespace obj_class {
extern std::string adata;
extern std::string dft;
extern std::string neighbors;
extern std::string enrollment;
extern std::string status;
extern std::string address;
extern std::string lfdb;  /* Lower Flow DB */
extern std::string flows; /* Supported flows */
extern std::string flow;
extern std::string keepalive;
extern std::string lowerflow;
extern std::string addr_alloc_req;
extern std::string addr_alloc_table;
}; // namespace obj_class

namespace obj_name {
extern std::string adata;
extern std::string dft;
extern std::string neighbors;
extern std::string enrollment;
extern std::string status;
extern std::string address;
extern std::string lfdb;
extern std::string whatevercast;
extern std::string flows;
extern std::string keepalive;
extern std::string lowerflow;
extern std::string addr_alloc_table;
}; // namespace obj_name

/* Time window to compute statistics about management traffic. */
#define RL_NEIGHFLOW_STATS_PERIOD 20

enum class EnrollState {
    NEIGH_NONE = 0,

    NEIGH_ENROLLING,
    NEIGH_ENROLLED,

    NEIGH_STATE_LAST,
};

enum class PolicyParamType {
    INT = 0,
    BOOL,
    UNDEFINED,
};

struct PolicyParam {
    PolicyParamType type;
    union {
        bool b;
        int i;
    } value;

    PolicyParam();
    PolicyParam(bool param_value);
    PolicyParam(int param_value);

    friend std::ostream &operator<<(std::ostream &os, const PolicyParam &param);

    int set_value(const std::string &param_value);
    bool get_bool_value() const;
    int get_int_value() const;
};

struct Neighbor;
struct NeighFlow;

/* Temporary resources needed to carry out an enrollment procedure
 * (initiator or slave) on a NeighFlow. */
struct EnrollmentResources {
    RL_NODEFAULT_NONCOPIABLE(EnrollmentResources);
    EnrollmentResources(struct NeighFlow *f, bool initiator);
    ~EnrollmentResources();

    struct NeighFlow *nf;
    std::list<const CDAPMessage *> msgs;
    pthread_t th;
    pthread_cond_t msgs_avail;
    pthread_cond_t stopped;

    int refcnt;
};

/* Holds the information about an N-1 flow towards a neighbor IPCP. */
struct NeighFlow {
    /* Backpointer to the parent data structure. */
    Neighbor *neigh;

    std::string supp_dif;

    /* If this is a kernel-bound flow, port_id and lower_ipcp_id are
     * valid. */
    rl_port_t port_id;
    rl_ipcp_id_t lower_ipcp_id;

    /* If this is a kernel-bound flow, flow_fd is only used for close().
     * Otherwise, this is a management-only flow, and the file descriptor
     * is also used for I/O. */
    int flow_fd;

    /* Is this flow reliable or not? A management-only flow must be
     * reliable. */
    bool reliable;

    /* CDAP connection associated to this flow, if any. */
    CDAPConn *conn;

    time_t last_activity;

    EnrollState enroll_state;
    struct EnrollmentResources *enrollment_rsrc;
    struct EnrollmentResources *enrollment_rsrc_get(bool initiator);
    void enrollment_rsrc_put();

    int keepalive_tmrid;
    int pending_keepalive_reqs;

    /* Statistics about management traffic. */
    struct {
        struct {
            unsigned int bytes_sent;
            unsigned int bytes_recvd;
        } win[2];
        time_t t_last;
    } stats;

    RL_NODEFAULT_NONCOPIABLE(NeighFlow);
    NeighFlow(Neighbor *n, const std::string &supp_dif, rl_port_t pid, int ffd,
              rl_ipcp_id_t lid);
    ~NeighFlow();

    void keepalive_tmr_start();
    void keepalive_tmr_stop();
    void keepalive_timeout();

    void enroll_state_set(EnrollState st);
    const CDAPMessage *next_enroll_msg();
    void enrollment_commit();
    void enrollment_abort();

    int send_to_port_id(CDAPMessage *m, int invoke_id, const UipcpObject *obj);
};

/* Holds the information about a neighbor IPCP. */
struct Neighbor {
    /* Backpointer to the RIB. */
    struct uipcp_rib *rib;

    /* Name of the neighbor. */
    std::string ipcp_name;

    /* Did we initiate the enrollment procedure towards this neighbor
     * or were we the target? */
    bool initiator;

    /* Kernel-bound N-1 flows used for data transfers and optionally
     * management. */
    std::unordered_map<rl_port_t, NeighFlow *> flows;

    /* If not nullptr, a regular (non-kernel-bound) N-1 flow used for
     * management purposes. */
    NeighFlow *mgmt_only;

    /* If not nullptr, a regular (non-kernel-bound) N flow used for
     * management purposes. This may be used only if the N-1 DIFs
     * towards the neighbor do not support reliable flows. */
    NeighFlow *n_flow;

    /* A flag used as a lock to prevent flow_alloc from being called
     * concurrently, while at the same time performinc the flow allocation
     * outside the RIB lock. */
    bool flow_alloc_enabled;

    /* Last time we received a keepalive response from this neighbor.
     * We don't consider requests, as timeout on responses. */
    time_t unheard_since;

    RL_NODEFAULT_NONCOPIABLE(Neighbor);
    Neighbor(struct uipcp_rib *rib, const std::string &name);
    bool operator==(const Neighbor &other) const
    {
        return ipcp_name == other.ipcp_name;
    }
    bool operator!=(const Neighbor &other) const { return !(*this == other); }
    ~Neighbor();

    static const char *enroll_state_repr(EnrollState s);

    void mgmt_only_set(NeighFlow *nf);
    void n_flow_set(NeighFlow *nf);
    NeighFlow *mgmt_conn();
    const NeighFlow *mgmt_conn() const { return _mgmt_conn(); };
    bool has_flows() const { return !flows.empty(); }
    bool enrollment_complete() const;
    int flow_alloc(const char *supp_dif_name);

    int neigh_sync_obj(const NeighFlow *nf, bool create,
                       const std::string &obj_class,
                       const std::string &obj_name,
                       const UipcpObject *obj_value) const;

    int neigh_sync_rib(NeighFlow *nf) const;

private:
    const NeighFlow *_mgmt_conn() const;
};

class ScopeLock {
public:
    RL_NODEFAULT_NONCOPIABLE(ScopeLock);
    ScopeLock(pthread_mutex_t &m, bool v = false) : mutex(m), verb(v)
    {
        pthread_mutex_lock(&mutex);
        if (verb) {
            PD("lock.acquire\n");
        }
    }
    ~ScopeLock()
    {
        if (verb) {
            PD("lock.release\n");
        }
        pthread_mutex_unlock(&mutex);
    }

private:
    pthread_mutex_t &mutex;
    bool verb;
};

#ifdef RL_DEBUG
#define RL_LOCK_ASSERT(_lock, _locked)                                         \
    do {                                                                       \
        int ret = pthread_mutex_trylock(_lock);                                \
        assert(!(_locked && ret == 0));                                        \
        assert(!(!_locked && ret == EBUSY));                                   \
        if (!_locked) {                                                        \
            pthread_mutex_unlock(_lock);                                       \
        }                                                                      \
    } while (0)
#else
#define RL_LOCK_ASSERT(_lock, _locked)
#endif

struct dft {
    /* Backpointer to parent data structure. */
    struct uipcp_rib *rib;

    RL_NODEFAULT_NONCOPIABLE(dft);
    dft(struct uipcp_rib *_ur) : rib(_ur) {}
    virtual ~dft() {}

    virtual void dump(std::stringstream &ss) const = 0;

    virtual int lookup_entry(const std::string &appl_name, rlm_addr_t &dstaddr,
                             const rlm_addr_t preferred,
                             uint32_t cookie) const                    = 0;
    virtual int appl_register(const struct rl_kmsg_appl_register *req) = 0;
    virtual void update_address(rlm_addr_t new_addr)                   = 0;
    virtual int rib_handler(const CDAPMessage *rm, NeighFlow *nf)      = 0;
    virtual int sync_neigh(NeighFlow *nf, unsigned int limit) const    = 0;
    virtual int neighs_refresh(size_t limit)                           = 0;
};

struct flow_allocator {
    /* Backpointer to parent data structure. */
    struct uipcp_rib *rib;

    /* Id to be used with incoming flow allocation request. */
    uint32_t kevent_id_cnt;

    RL_NODEFAULT_NONCOPIABLE(flow_allocator);
    flow_allocator(struct uipcp_rib *_ur) : rib(_ur), kevent_id_cnt(1) {}
    virtual ~flow_allocator() {}

    virtual void dump(std::stringstream &ss) const          = 0;
    virtual void dump_memtrack(std::stringstream &ss) const = 0;

    virtual int fa_req(struct rl_kmsg_fa_req *req)    = 0;
    virtual int fa_resp(struct rl_kmsg_fa_resp *resp) = 0;

    virtual int flow_deallocated(struct rl_kmsg_flow_deallocated *req) = 0;

    virtual int flows_handler_create(const CDAPMessage *rm)   = 0;
    virtual int flows_handler_create_r(const CDAPMessage *rm) = 0;
    virtual int flows_handler_delete(const CDAPMessage *rm)   = 0;

    int rib_handler(const CDAPMessage *rm, NeighFlow *nf);
};

struct lfdb {
    /* Backpointer to parent data structure. */
    struct uipcp_rib *rib;

    RL_NODEFAULT_NONCOPIABLE(lfdb);
    lfdb(struct uipcp_rib *_ur) : rib(_ur) {}
    virtual ~lfdb() {}

    virtual void dump(std::stringstream &ss) const         = 0;
    virtual void dump_routing(std::stringstream &ss) const = 0;

    virtual const LowerFlow *find(const NodeId &local_node,
                                  const NodeId &remote_node) const        = 0;
    virtual LowerFlow *find(const NodeId &local_node,
                            const NodeId &remote_node)                    = 0;
    virtual bool add(const LowerFlow &lf)                                 = 0;
    virtual bool del(const NodeId &local_node, const NodeId &remote_node) = 0;
    virtual void update_local(const std::string &neigh_name)              = 0;
    virtual void update_routing()                                         = 0;
    virtual int flow_state_update(struct rl_kmsg_flow_state *upd)         = 0;

    virtual int rib_handler(const CDAPMessage *rm, NeighFlow *nf) = 0;

    virtual int sync_neigh(NeighFlow *nf, unsigned int limit) const = 0;
    virtual int neighs_refresh(size_t limit)                        = 0;
};

struct addr_allocator {
    /* Backpointer to parent data structure. */
    struct uipcp_rib *rib;

    RL_NODEFAULT_NONCOPIABLE(addr_allocator);
    addr_allocator(struct uipcp_rib *_ur) : rib(_ur) {}
    virtual ~addr_allocator() {}

    virtual void dump(std::stringstream &ss) const                  = 0;
    virtual rlm_addr_t allocate()                                   = 0;
    virtual int rib_handler(const CDAPMessage *rm, NeighFlow *nf)   = 0;
    virtual int sync_neigh(NeighFlow *nf, unsigned int limit) const = 0;
    virtual int param_mod(const std::string &name, const std::string &value)
    {
        return -1;
    }
};

extern std::unordered_map<std::string, std::unordered_set<std::string>>
    available_policies;

struct uipcp_rib {
    /* Backpointer to parent data structure. */
    struct uipcp *uipcp;

    /* std::string cache for uipcp->name. */
    std::string myname;

    /* File descriptor used to receive and send mgmt PDUs. */
    int mgmtfd;

    /* RIB lock. */
    pthread_mutex_t mutex;

    typedef int (uipcp_rib::*rib_handler_t)(const CDAPMessage *rm,
                                            NeighFlow *nf);
    std::unordered_map<std::string, rib_handler_t> handlers;

    /* Positive if this IPCP is enrolled to the DIF, zero otherwise.
     * When we allocate a flow towards a candidate neighbor, we don't
     * have to carry out the whole enrollment procedure if we are already
     * enrolled. */
    int enrolled;

    /* True if this IPCP is allowed to act as enroller for other IPCPs. */
    bool enroller_enabled;

    /* Enrollment resources that have been used and can be released. */
    std::list<EnrollmentResources *> used_enrollment_resources;

    /* True if the name of this IPCP is registered to the IPCP itself.
     * Self-registration is used to receive N-flow allocation requests. */
    bool self_registered;
    bool self_registration_needed;

    /* IPCP address .*/
    rlm_addr_t myaddr;

    /* Lower DIFs. */
    std::list<std::string> lower_difs;

    /* A map containing the values for policy parameters
     * that can be tuned by the administrator. */
    std::unordered_map<std::string,
                       std::unordered_map<std::string, PolicyParam>>
        params_map;

    /* Neighbors. We keep track of all the NeighborCandidate objects seen,
     * even for candidates that have no lower DIF in common with us. This
     * is used to implement propagation of the CandidateNeighbors information,
     * so that all the IPCPs in the DIF know their potential candidate
     * neighbors.*/
    std::unordered_map<std::string, Neighbor *> neighbors;
    std::unordered_map<std::string, NeighborCandidate> neighbors_seen;
    std::unordered_set<std::string> neighbors_cand;
    std::unordered_set<std::string> neighbors_deleted;

    /* A map of current policies. */
    std::unordered_map<std::string, std::string> policies;

    /* Table used to carry on distributed address allocation.
     * It maps (address allocated) --> (requestor address). */
    struct addr_allocator *addra;

    /* Directory Forwarding Table. */
    struct dft *dft;

    /* Lower Flow Database. */
    struct lfdb *lfdb;

    /* Timer ID for LFDB synchronization with neighbors. */
    int sync_tmrid;

    /* For A-DATA messages. */
    InvokeIdMgr invoke_id_mgr;

    /* For supported flows. */
    struct flow_allocator *fa;

#ifdef RL_USE_QOS_CUBES
    /* Available QoS cubes. */
    std::map<std::string, struct rl_flow_config> qos_cubes;
#endif /* RL_USE_QOS_CUBES */

    /* Timer ID for age increment of LFDB entries. */
    int age_incr_tmrid;

    /* Time interval (in seconds) between two consecutive increments
     * of the age of LFDB entries. */
    static constexpr int kAgeIncrIntval = 2;

    /* Max age (in seconds) for an LFDB entry not to be discarded. */
    static constexpr int kAgeMax = 120;

    /* Time interval (in seconds) between two consecutive periodic
     * RIB synchronizations. */
    static constexpr int kRIBRefreshIntval = 30;

    /* Default value for keepalive parameter. */
    static constexpr int kKeepaliveTimeout = 10;

    /* Timeout intervals are expressed in milliseconds. */
    static constexpr int kKeepaliveThresh = 3;
    static constexpr int kEnrollTimeout   = 7000;

    /* Default value for the A timer in milliseconds. */
    static constexpr int kATimerMsecsDflt = 20;

    /* Default value for the R timer in milliseconds. */
    static constexpr int kRtxTimerMsecsDflt = 1000;

    /* Default value for the maximum length of the retransmission queue
     * (in PDUs). */
    static constexpr int kRtxQueueMaxLen = 512;

    /* Default value for the flow control initial credit (windows size in terms
       of PDUs). */
    static constexpr int kFlowControlInitialCredit = 512;

    /* Default value for the maximum length of the flow control closed window
     * queue (in terms of PDUs). */
    static constexpr int kFlowControlMaxCwqLen = 128;

    RL_NODEFAULT_NONCOPIABLE(uipcp_rib);
    uipcp_rib(struct uipcp *_u);
    ~uipcp_rib();

    char *dump() const;

    Neighbor *get_neighbor(const std::string &neigh_name, bool create);
    int del_neighbor(const std::string &neigh_name);
    int neigh_fa_req_arrived(const struct rl_kmsg_fa_req_arrived *req);
    int neigh_n_fa_req_arrived(const struct rl_kmsg_fa_req_arrived *req);
    void allocate_n_flows();

    int update_lower_difs(int reg, std::string lower_dif);
    int register_to_lower(const char *dif_name, bool reg);
    int register_to_lower_one(const char *lower_dif, bool reg);
    int realize_registrations(bool reg);
    int enroller_enable(bool enable);

    rlm_addr_t addr_allocate() { return addra->allocate(); };
    int set_address(rlm_addr_t address);
    void update_address(rlm_addr_t new_addr);
    rlm_addr_t lookup_node_address(const std::string &node_name) const;
    std::string lookup_neighbor_by_address(rlm_addr_t address);
    void check_for_address_conflicts();

    NeighborCandidate neighbor_cand_get() const;
    int lookup_neigh_flow_by_port_id(rl_port_t port_id, NeighFlow **nfp);
    void neigh_flow_prune(NeighFlow *nf);
    int enroll(const char *neigh_name, const char *supp_dif_name,
               int wait_for_completion);
    void trigger_re_enrollments();
    void clean_enrollment_resources();

    int recv_msg(char *serbuf, int serlen, NeighFlow *nf);
    int send_to_dst_addr(CDAPMessage *m, rlm_addr_t dst_addr,
                         const UipcpObject *obj);
    int send_to_myself(CDAPMessage *m, const UipcpObject *obj);

    /* Synchronize with neighbors. */
    int neighs_sync_obj_excluding(const Neighbor *exclude, bool create,
                                  const std::string &obj_class,
                                  const std::string &obj_name,
                                  const UipcpObject *obj_value) const;
    int neighs_sync_obj_all(bool create, const std::string &obj_class,
                            const std::string &obj_name,
                            const UipcpObject *obj_value) const;

    /* Receive info from neighbors. */
    int cdap_dispatch(const CDAPMessage *rm, NeighFlow *nf);

    /* RIB handlers for received CDAP messages. */
    int dft_handler(const CDAPMessage *rm, NeighFlow *nf)
    {
        return dft->rib_handler(rm, nf);
    };
    int neighbors_handler(const CDAPMessage *rm, NeighFlow *nf);
    int lfdb_handler(const CDAPMessage *rm, NeighFlow *nf)
    {
        return lfdb->rib_handler(rm, nf);
    };
    int flows_handler(const CDAPMessage *rm, NeighFlow *nf)
    {
        return fa->rib_handler(rm, nf);
    };
    int keepalive_handler(const CDAPMessage *rm, NeighFlow *nf);
    int status_handler(const CDAPMessage *rm, NeighFlow *nf);
    int addr_alloc_table_handler(const CDAPMessage *rm, NeighFlow *nf)
    {
        return addra->rib_handler(rm, nf);
    }

    void neighs_refresh();
    void neighs_refresh_tmr_restart();
    void age_incr_tmr_restart();
    void age_incr();

    int policy_mod(const std::string &component,
                   const std::string &policy_name);
    int policy_param_mod(const std::string &component,
                         const std::string &param_name,
                         const std::string &param_value);

    int policy_list(const struct rl_cmsg_ipcp_policy_list_req *req,
                    std::stringstream &msg);

    int policy_param_list(const struct rl_cmsg_ipcp_policy_param_list_req *req,
                          std::stringstream &msg);

    template <class T>
    T get_param_value(const std::string &component,
                      const std::string &param_name);

    void lock() { pthread_mutex_lock(&mutex); }
    void unlock() { pthread_mutex_unlock(&mutex); }

private:
#ifdef RL_USE_QOS_CUBES
    int load_qos_cubes(const char *);
#endif /* RL_USE_QOS_CUBES */
};

template <>
bool uipcp_rib::get_param_value<bool>(const std::string &component,
                                      const std::string &param_name);

template <>
int uipcp_rib::get_param_value<int>(const std::string &component,
                                    const std::string &param_name);

static inline void
reliable_spec(struct rina_flow_spec *spec)
{
    rl_flow_spec_default(spec);
    spec->max_sdu_gap       = 0;
    spec->in_order_delivery = 1;
}

static inline bool
is_reliable_spec(const struct rina_flow_spec *spec)
{
    return spec->max_sdu_gap == 0 && spec->in_order_delivery == 1;
}

int uipcp_do_register(struct uipcp *uipcp, const char *dif_name,
                      const char *local_name, int reg);

int mgmt_write_to_local_port(struct uipcp *uipcp, rl_port_t local_port,
                             void *buf, size_t buflen);

void normal_mgmt_only_flow_ready(struct uipcp *uipcp, int fd, void *opaque);

#define UIPCP_RIB(_u) static_cast<uipcp_rib *>((_u)->priv)

/*
 * Default implementation for IPCP components.
 */

struct dft_default : public dft {
    /* Directory Forwarding Table, mapping application name (std::string)
     * to a set of nodes that registered that name. All nodes are considered
     * equivalent. */
    std::multimap<std::string, DFTEntry> dft_table;

    RL_NODEFAULT_NONCOPIABLE(dft_default);
    dft_default(struct uipcp_rib *_ur) : dft(_ur) {}
    ~dft_default() {}

    void dump(std::stringstream &ss) const override;

    int lookup_entry(const std::string &appl_name, rlm_addr_t &dstaddr,
                     const rlm_addr_t preferred,
                     uint32_t cookie) const override;
    int appl_register(const struct rl_kmsg_appl_register *req) override;
    void update_address(rlm_addr_t new_addr) override;
    int rib_handler(const CDAPMessage *rm, NeighFlow *nf) override;
    int sync_neigh(NeighFlow *nf, unsigned int limit) const override;
    int neighs_refresh(size_t limit) override;
};

struct flow_allocator_default : public flow_allocator {
    RL_NODEFAULT_NONCOPIABLE(flow_allocator_default);
    flow_allocator_default(struct uipcp_rib *_ur) : flow_allocator(_ur) {}
    ~flow_allocator_default() {}

    void dump(std::stringstream &ss) const override;
    void dump_memtrack(std::stringstream &ss) const override;

    std::unordered_map<std::string, FlowRequest> flow_reqs;
    std::unordered_map<unsigned int, FlowRequest> flow_reqs_tmp;

    int fa_req(struct rl_kmsg_fa_req *req) override;
    int fa_resp(struct rl_kmsg_fa_resp *resp) override;

    int flow_deallocated(struct rl_kmsg_flow_deallocated *req) override;

    int flows_handler_create(const CDAPMessage *rm) override;
    int flows_handler_create_r(const CDAPMessage *rm) override;
    int flows_handler_delete(const CDAPMessage *rm) override;

private:
    void flowspec2flowcfg(const struct rina_flow_spec *spec,
                          struct rl_flow_config *cfg) const;
    void policies2flowcfg(struct rl_flow_config *cfg, const QosSpec &q,
                          const ConnPolicies &p);
};

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

struct lfdb_default : public lfdb {
    /* Lower Flow Database. */
    std::unordered_map<NodeId, std::unordered_map<NodeId, LowerFlow>> db;

    RoutingEngine re;

    RL_NODEFAULT_NONCOPIABLE(lfdb_default);
    lfdb_default(struct uipcp_rib *_ur) : lfdb(_ur), re(_ur) {}
    ~lfdb_default() {}

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
};

struct addr_allocator_distributed : public addr_allocator {
    /* Table used to carry on distributed address allocation.
     * It maps (address allocated) --> (requestor address). */
    std::unordered_map<rlm_addr_t, AddrAllocRequest> addr_alloc_table;

    RL_NODEFAULT_NONCOPIABLE(addr_allocator_distributed);
    addr_allocator_distributed(struct uipcp_rib *_ur)
        : addr_allocator(_ur), nack_wait_secs(4)
    {
    }
    ~addr_allocator_distributed() {}

    void dump(std::stringstream &ss) const override;
    rlm_addr_t allocate() override;
    int rib_handler(const CDAPMessage *rm, NeighFlow *nf) override;
    int sync_neigh(NeighFlow *nf, unsigned int limit) const override;
    int param_mod(const std::string &name, const std::string &value) override;

    /* How many seconds to wait for NACKs before considering the address
     * allocation successful. */
    unsigned int nack_wait_secs;
};

struct addr_allocator_manual : public addr_allocator_distributed {
    RL_NODEFAULT_NONCOPIABLE(addr_allocator_manual);
    addr_allocator_manual(struct uipcp_rib *_ur)
        : addr_allocator_distributed(_ur)
    {
    }
    rlm_addr_t allocate() override { return RL_ADDR_NULL; }
};

#endif /* __UIPCP_RIB_H__ */
