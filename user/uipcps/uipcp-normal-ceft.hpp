/*
 * Common functionalities for centralized fault tolerant components.
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

#include "uipcp-normal.hpp"

namespace rlite {

/* The CeftReplica class extends the Raft state machine by providing
 * generic glue functionalities to (i) send and receive messages to DIF members
 * through CDAP; (ii) keep track of pending client requests; (iii) implement
 * the timers needed by Raft.
 * Specific centralized-fault-tolerant components should extend this class
 * implementing the access to the specific resource and the reaction to input
 * CDAP messages. */
class CeftReplica : public raft::RaftSM {
    /* Size of a command in the replicated state machine log. */
    const size_t CommandSize;

    /* Name of the RIB object to use for Raft protocol communications. */
    const std::string RibObjName;

    /* Timer needed by the Raft state machine. */
    std::unique_ptr<TimeoutEvent> timer;
    raft::RaftTimerType timer_type;

    /* Support for client commands that are pending, waiting for
     * being applied to the replicated state machine. */
    struct PendingResp {
        std::unique_ptr<CDAPMessage> m;
        rlm_addr_t requestor_addr;
        raft::Term term;
        PendingResp() = default;
        PendingResp(std::unique_ptr<CDAPMessage> rm, rlm_addr_t addr,
                    raft::Term term)
            : m(std::move(rm)), requestor_addr(addr), term(term)
        {
        }
    };

    std::unordered_map<raft::LogIndex, std::unique_ptr<PendingResp>> pending;

    static std::string ReqVoteObjClass;
    static std::string ReqVoteRespObjClass;
    static std::string AppendEntriesObjClass;
    static std::string AppendEntriesRespObjClass;

protected:
    UipcpRib *rib = nullptr;
    static std::string DummyMessageObjClass;

public:
    RL_NODEFAULT_NONCOPIABLE(CeftReplica);
    CeftReplica(UipcpRib *rib, const std::string &smname,
                const raft::ReplicaId &myname, std::string logname,
                size_t cmd_size, const std::string rib_obj_name)
        : raft::RaftSM(smname, myname, logname, cmd_size, std::cerr, std::cout),
          CommandSize(cmd_size),
          RibObjName(rib_obj_name),
          rib(rib)
    {
    }
    virtual ~CeftReplica() {}

    int init(const std::list<raft::ReplicaId> &peers);
    int process_sm_output(raft::RaftSMOutput out);
    int process_timeout();
    int apply(raft::LogIndex index, raft::Term term,
              const char *const serbuf) override final;
    int rib_handler(const CDAPMessage *rm, const MsgSrcInfo &src);
    virtual int apply(const char *const serbuf, CDAPMessage *const rm) = 0;
    using CommandToSubmit =
        std::pair<std::unique_ptr<char[]>, std::unique_ptr<CDAPMessage>>;
    virtual int replica_process_rib_msg(
        const CDAPMessage *rm, rlm_addr_t src_addr,
        std::vector<CommandToSubmit> *commands) = 0;
};

/* The CeftClient class provides the client-side generic glue functionalities
 * to interact with a cluster of Raft replicas. Functionalities in detail:
 * (i) send and receive messages to the replicas through CDAP; (ii) keep track
 * of pending requests awaiting for a response from the replicas;
 * (iii) implement the necessary timers to let pending requests timeout.
 * Specific centralized-fault-tolerant components should extend this class to
 * implement the access to the specific resource and to react to input CDAP
 * messages. Also the CeftClient::PendingReq may be extended to include
 * additional client-side information. */
class CeftClient {
protected:
    UipcpRib *rib = nullptr;
    std::list<raft::ReplicaId> replicas;
    /* The leader, if we know who it is, otherwise the empty
     * string. */
    raft::ReplicaId leader_id;
    /* The replica that responded first to an M_READ, if any. */
    raft::ReplicaId reader_id;
    std::unique_ptr<TimeoutEvent> timer;

    struct PendingReq {
        raft::ReplicaId replica;
        gpb::OpCode op_code;
        std::chrono::system_clock::time_point t;
        PendingReq() = default;
        PendingReq(gpb::OpCode op_code, Msecs timeout) : op_code(op_code)
        {
            t = std::chrono::system_clock::now() + timeout;
        }
        virtual ~PendingReq() {}
        virtual std::unique_ptr<PendingReq> clone() const = 0;
    };
    std::unordered_map</*invoke_id*/ int, std::unique_ptr<PendingReq>> pending;

    enum class OpSemantics { Get, Put };

    int send_to_replicas(std::unique_ptr<CDAPMessage> m,
                         std::unique_ptr<PendingReq> pr, OpSemantics sem);
    void mod_pending_timer();

public:
    RL_NODEFAULT_NONCOPIABLE(CeftClient);
    CeftClient(UipcpRib *rib, std::list<raft::ReplicaId> names)
        : rib(rib), replicas(std::move(names))
    {
    }
    virtual ~CeftClient() {}
    int process_timeout();
    int rib_handler(const CDAPMessage *rm, const MsgSrcInfo &src);

    /* Called from rib_handler() to perform implementation specific
     * processing.*/
    virtual int client_process_rib_msg(const CDAPMessage *rm,
                                       CeftClient::PendingReq *const bpr,
                                       rlm_addr_t src_addr) = 0;

    /* For external hints. */
    void set_leader_id(const raft::ReplicaId &name)
    {
        leader_id = reader_id = name;
    }

    /* Timeout in seconds for client requests to the replicas. */
    static constexpr int kTimeoutSecs = 5;
};

} // namespace rlite
