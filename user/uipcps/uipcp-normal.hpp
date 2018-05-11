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
#include <set>
#include <list>
#include <ctime>
#include <sstream>
#include <utility>
#include <memory>
#include <thread>
#include <mutex>
#include <functional>
#include <condition_variable>
#include <chrono>

#include "rlite/common.h"
#include "rlite/utils.h"
#include "rlite/uipcps-msg.h"
#include "rlite/cpputils.hpp"
#include "rlite/raft.hpp"
#include "rina/cdap.hpp"

#include "uipcp-container.h"
#include "BaseRIB.pb.h"

namespace Uipcps {

#ifdef RL_MEMTRACK
#define rl_new(_exp, _ty)                                                      \
    ({                                                                         \
        rl_mt_adjust(1, _ty);                                                  \
        new _exp;                                                              \
    })
#define rl_delete(_exp, _ty)                                                   \
    do {                                                                       \
        rl_mt_adjust(-1, _ty);                                                 \
        delete _exp;                                                           \
    } while (0)
#else /* RL_MEMTRACK */
#define rl_new(_exp, _ty) new _exp
#define rl_delete(_exp, _ty) delete _exp
#endif /* RL_MEMTRACK */

using Msecs = std::chrono::milliseconds;
using Secs  = std::chrono::seconds;

enum class PolicyParamType {
    Int = 0,
    Bool,
    String,
    Duration,
    Undefined,
};

struct PolicyParam {
    PolicyParamType type;
    union {
        bool b;
        int i;
    } value;
    int min;
    int max;
    std::string stringval;
    Msecs durval;

    PolicyParam();
    PolicyParam(bool param_value);
    PolicyParam(int param_value, int range_min = 0, int range_max = 0);
    PolicyParam(const std::string &s);
    PolicyParam(const Msecs durval);

    friend std::ostream &operator<<(std::ostream &os, const PolicyParam &param);

    int set_value(const std::string &param_value, std::string *error_reason);
    bool get_bool_value() const;
    int get_int_value() const;
    std::string get_string_value() const;
    Msecs get_duration_value() const;
};

struct Neighbor;
struct NeighFlow;
struct UipcpRib;

struct TimeoutEvent {
    Msecs delta;
    struct uipcp *uipcp = nullptr;
    void *arg           = nullptr;
    uipcp_tmr_cb_t cb   = nullptr;
    int tmrid           = -1;

    RL_NONCOPIABLE(TimeoutEvent);
    RL_NONMOVABLE(TimeoutEvent);
    TimeoutEvent(Msecs d, struct uipcp *u, void *a, uipcp_tmr_cb_t _cb);
    void clear();
    void fired();
    bool is_pending() const { return tmrid != -1; }
    ~TimeoutEvent() { clear(); }
};

enum class EnrollState {
    NEIGH_NONE = 0,

    NEIGH_ENROLLING,
    NEIGH_ENROLLED,

    NEIGH_STATE_LAST,
};

/* Holds the information about an N-1 flow towards a neighbor IPCP. */
struct NeighFlow {
    /* Backpointer to the parent data structure. */
    UipcpRib *rib;

    /* Name of the neighbor IPCP (same as Neighbor::ipcp_name of
     * the parent Neighbor object). */
    std::string neigh_name;
    std::string supp_dif;

    /* If this is a kernel-bound flow, port_id and lower_ipcp_id are
     * valid. */
    rl_port_t port_id;
    rl_ipcp_id_t lower_ipcp_id;

    /* If this is a kernel-bound flow, flow_fd is only used for close().
     * Otherwise, this is a management-only flow, and the file descriptor
     * is also used for I/O. In any case the flow_fd is a valid file
     * descriptor. */
    int flow_fd;

    /* Is this flow reliable or not? A management-only flow must be
     * reliable. */
    bool reliable;

    /* CDAP connection associated to this flow, if any. */
    std::unique_ptr<CDAPConn> conn;

    EnrollState enroll_state;
    int pending_keepalive_reqs;
    std::chrono::system_clock::time_point last_activity;

    /* Did we initiate the enrollment procedure towards the neighbor
     * or were we the target? */
    bool initiator = false;

    /* Statistics about management traffic. */
    struct {
        struct {
            unsigned int bytes_sent;
            unsigned int bytes_recvd;
        } win[2];
        std::chrono::system_clock::time_point t_last;
    } stats;

    RL_NODEFAULT_NONCOPIABLE(NeighFlow);
    NeighFlow(UipcpRib *parent, const std::string &ipcp_name,
              const std::string &supp_dif, rl_port_t pid, int ffd,
              rl_ipcp_id_t lid);
    ~NeighFlow();

    void keepalive_tmr_start();
    void keepalive_tmr_stop();

    void enroll_state_set(EnrollState st);

    int send_to_port_id(CDAPMessage *m, int invoke_id = 0,
                        const ::google::protobuf::MessageLite *obj = nullptr);
    int sync_obj(bool create, const std::string &obj_class,
                 const std::string &obj_name,
                 const ::google::protobuf::MessageLite *obj = nullptr);

    static std::string KeepaliveObjName;
    static std::string KeepaliveObjClass;
};

/* Holds the information about a neighbor IPCP. */
struct Neighbor {
    /* Backpointer to the RIB. */
    UipcpRib *rib;

    /* Name of the neighbor. */
    std::string ipcp_name;

    /* Kernel-bound N-1 flows used for data transfers and optionally
     * management. NeighFlow objects (including the ones below) are
     * kept using raw pointers, as the RIB lock is never released while
     * we have a reference to one of these objects. */
    std::unordered_map<rl_port_t, std::shared_ptr<NeighFlow>> flows;

    /* If not nullptr, a regular (non-kernel-bound) N-1 flow used for
     * management purposes. */
    std::shared_ptr<NeighFlow> mgmt_only;

    /* If not nullptr, a regular (non-kernel-bound) N-flow used for
     * management purposes. This may be used only if the N-1 DIFs
     * towards the neighbor do not support reliable flows. */
    std::shared_ptr<NeighFlow> n_flow;

    /* A flag used as a lock to prevent flow_alloc from being called
     * concurrently, while at the same time performinc the flow allocation
     * outside the RIB lock. */
    bool flow_alloc_enabled;

    /* Last time we received a keepalive response from this neighbor.
     * We don't consider requests, as timeout on responses. */
    std::chrono::system_clock::time_point unheard_since;

    RL_NODEFAULT_NONCOPIABLE(Neighbor);
    Neighbor(UipcpRib *rib, const std::string &name);
    bool operator==(const Neighbor &other) const
    {
        return ipcp_name == other.ipcp_name;
    }
    bool operator!=(const Neighbor &other) const { return !(*this == other); }
    ~Neighbor();

    static const char *enroll_state_repr(EnrollState s);

    void mgmt_only_set(std::shared_ptr<NeighFlow> nf);
    void n_flow_set(std::shared_ptr<NeighFlow> nf);
    std::shared_ptr<NeighFlow> &mgmt_conn();
    bool has_flows() const { return !flows.empty(); }
    bool enrollment_complete();
    int flow_alloc(const char *supp_dif_name);

    static std::string TableName;
    static std::string ObjClass;
};

#ifdef RL_DEBUG
#define RL_LOCK_ASSERT(_lock, _locked)                                         \
    do {                                                                       \
        bool ret = _lock.try_lock();                                           \
        assert(!ret || !_locked);                                              \
        assert(ret || _locked);                                                \
        if (ret) {                                                             \
            _lock.unlock();                                                    \
        }                                                                      \
    } while (0)
#else
#define RL_LOCK_ASSERT(_lock, _locked)
#endif

/* Naming service, to translate names to addresses. */
struct DFT {
    /* Backpointer to parent data structure. */
    UipcpRib *rib;

    RL_NODEFAULT_NONCOPIABLE(DFT);
    DFT(UipcpRib *_ur) : rib(_ur) {}
    virtual ~DFT() {}

    virtual int reconfigure() { return 0; }
    virtual void dump(std::stringstream &ss) const                        = 0;
    virtual int lookup_req(const std::string &appl_name, std::string *dst_node,
                           const std::string &preferred, uint32_t cookie) = 0;
    virtual int appl_register(const struct rl_kmsg_appl_register *req)    = 0;
    virtual int rib_handler(const CDAPMessage *rm,
                            std::shared_ptr<NeighFlow> const &nf,
                            std::shared_ptr<Neighbor> const &neigh,
                            rlm_addr_t src_addr)                          = 0;
    virtual int sync_neigh(const std::shared_ptr<NeighFlow> &nf,
                           unsigned int limit) const
    {
        return 0;
    }
    virtual int neighs_refresh(size_t limit) { return 0; }

    static std::string TableName;
    static std::string ObjClass;
    static std::string Prefix;
};

/* Allocation and deallocation of N-flows used applications. */
struct FlowAllocator {
    /* Backpointer to parent data structure. */
    UipcpRib *rib;

    /* Id to be used with incoming flow allocation request. */
    uint32_t kevent_id_cnt;

    RL_NODEFAULT_NONCOPIABLE(FlowAllocator);
    FlowAllocator(UipcpRib *_ur) : rib(_ur), kevent_id_cnt(1) {}
    virtual ~FlowAllocator() {}

    virtual void dump(std::stringstream &ss) const          = 0;
    virtual void dump_memtrack(std::stringstream &ss) const = 0;

    virtual int fa_req(struct rl_kmsg_fa_req *req,
                       const std::string &remote_node) = 0;
    virtual int fa_resp(struct rl_kmsg_fa_resp *resp)  = 0;

    virtual int flow_deallocated(struct rl_kmsg_flow_deallocated *req) = 0;

    virtual int flows_handler_create(const CDAPMessage *rm)   = 0;
    virtual int flows_handler_create_r(const CDAPMessage *rm) = 0;
    virtual int flows_handler_delete(const CDAPMessage *rm)   = 0;

    int rib_handler(const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
                    std::shared_ptr<Neighbor> const &neigh,
                    rlm_addr_t src_addr);

    static std::string TableName;
    static std::string ObjClass;
    static std::string FlowObjClass;
    static std::string Prefix;
};

/* Lower Flows Database and dissemination of routing information,
 * related to (N-1)-flows. */
struct Routing {
    /* Backpointer to parent data structure. */
    UipcpRib *rib;

    RL_NODEFAULT_NONCOPIABLE(Routing);
    Routing(UipcpRib *_ur) : rib(_ur) {}
    virtual ~Routing() {}

    virtual void dump(std::stringstream &ss) const         = 0;
    virtual void dump_routing(std::stringstream &ss) const = 0;

    virtual void update_local(const std::string &neigh_name) {}
    virtual void update_kernel(bool force = true) {}
    virtual int flow_state_update(struct rl_kmsg_flow_state *upd) { return 0; }

    /* Called to flush all the local entries related to a given neighbor. */
    virtual void neigh_disconnected(const std::string &neigh_name) {}

    virtual int rib_handler(const CDAPMessage *rm,
                            std::shared_ptr<NeighFlow> const &nf,
                            std::shared_ptr<Neighbor> const &neigh,
                            rlm_addr_t src_addr)
    {
        return 0;
    }

    virtual int sync_neigh(const std::shared_ptr<NeighFlow> &nf,
                           unsigned int limit) const
    {
        return 0;
    }
    virtual int neighs_refresh(size_t limit) { return 0; }
    virtual void age_incr() {}
    virtual int route_mod(const struct rl_cmsg_ipcp_route_mod *req)
    {
        return 0;
    }

    static std::string TableName;
    static std::string ObjClass;
    static std::string Prefix;
};

/* Address allocation for the members of the N-DIF. */
struct AddrAllocator {
    /* Backpointer to parent data structure. */
    UipcpRib *rib;

    RL_NODEFAULT_NONCOPIABLE(AddrAllocator);
    AddrAllocator(UipcpRib *_ur) : rib(_ur) {}
    virtual ~AddrAllocator() {}

    virtual int reconfigure() { return 0; }
    virtual void dump(std::stringstream &ss) const                       = 0;
    virtual int allocate(const std::string &ipcp_name, rlm_addr_t *addr) = 0;
    virtual int rib_handler(const CDAPMessage *rm,
                            std::shared_ptr<NeighFlow> const &nf,
                            std::shared_ptr<Neighbor> const &neigh,
                            rlm_addr_t src_addr)                         = 0;
    virtual int sync_neigh(const std::shared_ptr<NeighFlow> &nf,
                           unsigned int limit) const
    {
        return 0;
    }

    static std::string TableName;
    static std::string ObjClass;
    static std::string Prefix;
};

/* An object that knows how to build, register and unregister a
 * policy for an IPCP component. */
struct PolicyBuilder {
    std::string name;
    std::function<void(UipcpRib *)> builder = [](UipcpRib *) {};
    std::list<std::string> paths;
    std::list<std::pair<std::string, PolicyParam>> params;

    PolicyBuilder(const std::string &policy_name) : name(policy_name) {}
    PolicyBuilder(const std::string &policy_name,
                  std::function<void(UipcpRib *)> fun,
                  std::list<std::string> ps                         = {},
                  std::list<std::pair<std::string, PolicyParam>> pp = {})
        : PolicyBuilder(policy_name)
    {
        builder = fun;
        paths   = std::move(ps);
        params  = std::move(pp);
    }
    bool operator<(const PolicyBuilder &o) const { return name < o.name; }
    bool operator==(const PolicyBuilder &o) const { return name == o.name; }
    operator std::string() { return name; }
};

/* Temporary resources needed to carry out an enrollment procedure
 * (initiator or slave) on a NeighFlow. */
struct EnrollmentResources {
    RL_NODEFAULT_NONCOPIABLE(EnrollmentResources);
    EnrollmentResources(std::shared_ptr<NeighFlow> const &f,
                        std::shared_ptr<Neighbor> const &ng, bool init);
    ~EnrollmentResources();

    std::shared_ptr<NeighFlow> nf;
    std::shared_ptr<Neighbor> neigh;
    int flow_fd; /* for debugging only */
    bool initiator;
    std::list<std::unique_ptr<const CDAPMessage>> msgs;
    std::thread th;
    std::condition_variable msgs_avail;
    std::condition_variable stopped;

    void enroller_thread();
    int enroller_default(std::unique_lock<std::mutex> &lk);
    void enrollee_thread();
    int enrollee_default(std::unique_lock<std::mutex> &lk);

    std::unique_ptr<const CDAPMessage> next_enroll_msg(
        std::unique_lock<std::mutex> &lk);
    void enrollment_commit();
    void enrollment_abort();

    /* Remove the stored shared pointer. */
    void set_terminated() { nf.reset(); }
    bool is_terminated() const { return nf == nullptr; }
};

/* Main class representing an IPCP. */
struct UipcpRib {
    /* Backpointer to parent data structure. */
    struct uipcp *uipcp = nullptr;

    /* std::string cache for uipcp->name. */
    std::string myname;

    /* File descriptor used to receive and send mgmt PDUs through
     * a kernel-bound flow. */
    int mgmtfd;

    /* RIB lock. */
    std::mutex mutex;

    struct periodic_task *tasks = nullptr;

    using RibHandler = std::function<int(
        UipcpRib &, const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
        std::shared_ptr<Neighbor> const &neigh, rlm_addr_t src_addr)>;
    struct RibHandlerInfo {
        RibHandler handler;
    };

    std::unordered_map<std::string, RibHandlerInfo> handlers;

    /* Positive if this IPCP is enrolled to the DIF, zero otherwise.
     * When we allocate a flow towards a candidate neighbor, we don't
     * have to carry out the whole enrollment procedure if we are already
     * enrolled. */
    int enrolled;

    /* True if this IPCP is allowed to act as enroller for other IPCPs. */
    bool enroller_enabled;

    /* True if the name of this IPCP is registered to the IPCP itself.
     * Self-registration is used to receive N-flow allocation requests. */
    bool self_registered;
    bool self_registration_needed;

    /* IPCP address .*/
    rlm_addr_t myaddr;

    /* Lower DIFs. */
    std::list<std::string> lower_difs;

    /* EFCP Data Transfer constants used by this DIF. */
    gpb::DataTransferConstants dt_constants;

    /* A map of current policies. */
    std::unordered_map<std::string, std::string> policies;

    /* A map containing the values for policy parameters
     * that can be tuned by the administrator. */
    std::unordered_map<std::string,
                       std::unordered_map<std::string, PolicyParam>>
        params_map;

    /* Neighbors. We keep track of all the gpb::NeighborCandidate objects seen,
     * even for candidates that have no lower DIF in common with us. This
     * is used to implement propagation of the CandidateNeighbors information,
     * so that all the IPCPs in the DIF know their potential candidate
     * neighbors.
     * We use std::shared_ptr to hold the Neighbor objects, in such a way that
     * we can temporarily release the RIB lock while keeping a reference
     * to the object. */
    std::unordered_map<std::string, std::shared_ptr<Neighbor>> neighbors;
    std::unordered_map<std::string, gpb::NeighborCandidate> neighbors_seen;
    std::unordered_set<std::string> neighbors_cand;
    std::unordered_set<std::string> neighbors_deleted;

    /* A map to keep the keepalive timers for all the NeighFlow objects. */
    std::unordered_map<int /*flow_fd*/, std::unique_ptr<TimeoutEvent>>
        keepalive_timers;

    /* A map to keep the temporary enrollment resources for all the
     * NeighFlow objects. */
    std::unordered_map<int /*flow_fd*/, std::unique_ptr<EnrollmentResources>>
        enrollment_resources;
    EnrollmentResources *enrollment_rsrc_get(
        std::shared_ptr<NeighFlow> const &nf,
        std::shared_ptr<Neighbor> const &neigh, bool initiator);

    /* Table of flow allocation requests that are pending because they are
     * waiting for DFT resolution. See UipcpRib::fa_req(). */
    std::unordered_map<std::string,
                       std::list<std::unique_ptr<struct rl_kmsg_fa_req>>>
        pending_fa_reqs;

    /* Called by the DFT when a name lookup has been resolved asynchronously. */
    void dft_lookup_resolved(const std::string &name,
                             const std::string &remote_node);

    std::unique_ptr<AddrAllocator> addra;

    /* Directory Forwarding Table. */
    std::unique_ptr<DFT> dft;

    /* Lower Flow Database. */
    std::unique_ptr<Routing> routing;

    /* Timer ID for LFDB synchronization with neighbors. */
    std::unique_ptr<TimeoutEvent> sync_timer;

    /* For A-DATA messages. */
    InvokeIdMgr invoke_id_mgr;

    /* For supported flows. */
    std::unique_ptr<FlowAllocator> fa;

#ifdef RL_USE_QOS_CUBES
    /* Available QoS cubes. */
    std::map<std::string, struct rl_flow_config> qos_cubes;
#endif /* RL_USE_QOS_CUBES */

    /* Timer ID for age increment of LFDB entries. */
    std::unique_ptr<TimeoutEvent> age_incr_timer;

    struct {
        uint64_t routing_table_compute;
        uint64_t fwd_table_compute;
        uint64_t fa_name_lookup_failed;
        uint64_t fa_request_issued;
        uint64_t fa_response_received;
        uint64_t fa_request_received;
        uint64_t fa_response_issued;
    } stats;

    /* Time interval (in seconds) between two consecutive periodic
     * RIB synchronizations. */
    static constexpr int kRIBRefreshIntvalSecs = 30;

    /* Default value for keepalive parameters. */
    static constexpr int kKeepaliveTimeoutSecs = 20;
    static constexpr int kKeepaliveThresh      = 3;

    /* Enrollment timeouts in milliseconds. */
    static constexpr int kEnrollTimeoutMsecs = 7000;

    /* Time window to compute statistics about management traffic (in seconds).
     */
    static constexpr int kNeighFlowStatsPeriod = 20;

    static std::string StatusObjClass;
    static std::string StatusObjName;
    static std::string DTConstantsObjClass;
    static std::string DTConstantsObjName;
    static std::string ADataObjClass;
    static std::string ADataObjName;
    static std::string EnrollmentObjClass;
    static std::string EnrollmentObjName;
    static std::string EnrollmentPrefix;
    static std::string LowerFlowObjClass;
    static std::string LowerFlowObjName;
    static std::string ResourceAllocPrefix;
    static std::string RibDaemonPrefix;

    RL_NODEFAULT_NONCOPIABLE(UipcpRib);
    UipcpRib(struct uipcp *_u);
    ~UipcpRib();

    void dump(std::stringstream &ss) const;
    void dump_rib_paths(std::stringstream &ss) const;
    void dump_stats(std::stringstream &ss) const;

    std::shared_ptr<Neighbor> get_neighbor(const std::string &neigh_name,
                                           bool create);
    int del_neighbor(std::string neigh_name, bool reconnect = false);
    int neigh_fa_req_arrived(const struct rl_kmsg_fa_req_arrived *req);
    int neigh_n_fa_req_arrived(const struct rl_kmsg_fa_req_arrived *req);
    void allocate_n_flows();

    int update_lower_difs(int reg, std::string lower_dif);
    int register_to_lower(const char *dif_name, bool reg);
    int register_to_lower_one(const char *lower_dif, bool reg);
    int realize_registrations(bool reg);
    int enroller_enable(bool enable);

    int addr_allocate(const std::string &ipcp_name, rlm_addr_t *addr)
    {
        return addra->allocate(ipcp_name, addr);
    };
    int set_address(rlm_addr_t address);
    void update_address(rlm_addr_t new_addr);
    rlm_addr_t lookup_node_address(const std::string &node_name) const;
    std::string lookup_neighbor_by_address(rlm_addr_t address);
    void check_for_address_conflicts();
    int update_ttl();

    gpb::NeighborCandidate neighbor_cand_get() const;
    int lookup_neigh_flow_by_port_id(rl_port_t port_id,
                                     std::shared_ptr<NeighFlow> *pnf,
                                     std::shared_ptr<Neighbor> *pneigh);

    int lookup_neigh_flow_by_flow_fd(int flow_fd,
                                     std::shared_ptr<NeighFlow> *pnf,
                                     std::shared_ptr<Neighbor> *pneigh);
    void neigh_flow_prune(const std::shared_ptr<NeighFlow> &nf);
    int enroll(const char *neigh_name, const char *supp_dif_name,
               int wait_for_completion);
    int neigh_disconnect(const std::string &neigh_name);
    int lower_dif_detach(const std::string &lower_dif);
    void enrollment_resources_cleanup();
    void trigger_re_enrollments();
    void keepalive_timeout(const std::shared_ptr<NeighFlow> &nf);

    int fa_req(struct rl_kmsg_fa_req *req);

    int recv_msg(char *serbuf, int serlen, std::shared_ptr<NeighFlow> nf,
                 std::shared_ptr<Neighbor> neigh,
                 rl_port_t port_id = RL_PORT_ID_NONE);
    int mgmt_bound_flow_write(const struct rl_mgmt_hdr *mhdr, void *buf,
                              size_t buflen);
    int obj_serialize(CDAPMessage *m,
                      const ::google::protobuf::MessageLite *obj);
    int send_to_dst_addr(std::unique_ptr<CDAPMessage> m, rlm_addr_t dst_addr,
                         const ::google::protobuf::MessageLite *obj = nullptr,
                         int *invoke_id                             = nullptr);
    int send_to_dst_node(std::unique_ptr<CDAPMessage> m, std::string node_name,
                         const ::google::protobuf::MessageLite *obj = nullptr,
                         int *invoke_id                             = nullptr);
    int send_to_myself(std::unique_ptr<CDAPMessage> m,
                       const ::google::protobuf::MessageLite *obj = nullptr);

    /* Synchronize with neighbors. */
    int neighs_sync_obj_excluding(
        const std::shared_ptr<Neighbor> &exclude, bool create,
        const std::string &obj_class, const std::string &obj_name,
        const ::google::protobuf::MessageLite *obj = nullptr) const;
    int neighs_sync_obj_all(
        bool create, const std::string &obj_class, const std::string &obj_name,
        const ::google::protobuf::MessageLite *obj = nullptr) const;
    int sync_rib(const std::shared_ptr<NeighFlow> &nf);

    /* Receive info from neighbors. */
    int cdap_dispatch(const CDAPMessage *rm,
                      std::shared_ptr<NeighFlow> const &nf,
                      std::shared_ptr<Neighbor> const &neigh,
                      rlm_addr_t src_addr);

    void rib_handler_register(std::string rib_path, RibHandler h);
    void rib_handler_unregister(std::string rib_path);

    /* RIB handlers for received CDAP messages. */
    int dft_handler(const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
                    std::shared_ptr<Neighbor> const &neigh, rlm_addr_t src_addr)
    {
        return dft->rib_handler(rm, nf, neigh, src_addr);
    };
    int neighbors_handler(const CDAPMessage *rm,
                          std::shared_ptr<NeighFlow> const &nf,
                          std::shared_ptr<Neighbor> const &neigh,
                          rlm_addr_t src_addr);
    int routing_handler(const CDAPMessage *rm,
                        std::shared_ptr<NeighFlow> const &nf,
                        std::shared_ptr<Neighbor> const &neigh,
                        rlm_addr_t src_addr)
    {
        return routing->rib_handler(rm, nf, neigh, src_addr);
    };
    int flows_handler(const CDAPMessage *rm,
                      std::shared_ptr<NeighFlow> const &nf,
                      std::shared_ptr<Neighbor> const &neigh,
                      rlm_addr_t src_addr)
    {
        return fa->rib_handler(rm, nf, neigh, src_addr);
    };
    int keepalive_handler(const CDAPMessage *rm,
                          std::shared_ptr<NeighFlow> const &nf,
                          std::shared_ptr<Neighbor> const &neigh,
                          rlm_addr_t src_addr);
    int status_handler(const CDAPMessage *rm,
                       std::shared_ptr<NeighFlow> const &nf,
                       std::shared_ptr<Neighbor> const &neigh,
                       rlm_addr_t src_addr);
    int addr_alloc_handler(const CDAPMessage *rm,
                           std::shared_ptr<NeighFlow> const &nf,
                           std::shared_ptr<Neighbor> const &neigh,
                           rlm_addr_t src_addr)
    {
        return addra->rib_handler(rm, nf, neigh, src_addr);
    }

    int lowerflow_handler(const CDAPMessage *rm,
                          std::shared_ptr<NeighFlow> const &nf,
                          std::shared_ptr<Neighbor> const &neigh,
                          rlm_addr_t src_addr);

    int policy_handler(const CDAPMessage *rm,
                       std::shared_ptr<NeighFlow> const &nf,
                       std::shared_ptr<Neighbor> const &neigh,
                       rlm_addr_t src_addr);

    int policy_param_handler(const CDAPMessage *rm,
                             std::shared_ptr<NeighFlow> const &nf,
                             std::shared_ptr<Neighbor> const &neigh,
                             rlm_addr_t src_addr);

    void neighs_refresh();
    void neighs_refresh_tmr_restart();
    void age_incr_tmr_restart();

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
    PolicyParamType get_param_type(const std::string &component,
                                   const std::string &param_name);

    void lock() { mutex.lock(); }
    void unlock() { mutex.unlock(); }

    /* Global map of available policies. Maps the name of each replaceable
     * component to a set of PolicyBuilder objects. Each PolicyBuilder object
     * describes a different policy (it contains a name and a function to build
     * and assign the policy). */
    static std::unordered_map<std::string, std::set<PolicyBuilder>>
        available_policies;
    static void addra_lib_init();
    static void dft_lib_init();
    static void fa_lib_init();
    static void routing_lib_init();
    static void ra_lib_init();

private:
#ifdef RL_USE_QOS_CUBES
    int load_qos_cubes(const char *);
#endif /* RL_USE_QOS_CUBES */
};

template <>
bool UipcpRib::get_param_value<bool>(const std::string &component,
                                     const std::string &param_name);

template <>
int UipcpRib::get_param_value<int>(const std::string &component,
                                   const std::string &param_name);

template <>
Msecs UipcpRib::get_param_value<Msecs>(const std::string &component,
                                       const std::string &param_name);

gpb::APName *apname2gpb(const std::string &name);
std::string apname2string(const gpb::APName &gname);

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

void normal_mgmt_only_flow_ready(struct uipcp *uipcp, int fd, void *opaque);

#define UIPCP_RIB(_u) (static_cast<UipcpRib *>((_u)->priv))

} // namespace Uipcps

#endif /* __UIPCP_RIB_H__ */
