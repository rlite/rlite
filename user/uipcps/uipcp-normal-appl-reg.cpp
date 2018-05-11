/*
 * Application registration support for normal uipcps.
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

#include <ctime>
#include <iterator>
#include <cstdlib>
#include <chrono>

#include "uipcp-normal.hpp"
#include "Raft.pb.h"

using namespace std;

namespace Uipcps {

class FullyReplicatedDFT : public DFT {
    /* Directory Forwarding Table, mapping application name (std::string)
     * to a set of nodes that registered that name. All nodes are considered
     * equivalent. */
    std::multimap<std::string, std::unique_ptr<gpb::DFTEntry>> dft_table;
    uint64_t seqnum_next = 1;

public:
    RL_NODEFAULT_NONCOPIABLE(FullyReplicatedDFT);
    FullyReplicatedDFT(UipcpRib *_ur) : DFT(_ur) {}
    ~FullyReplicatedDFT() {}

    void dump(std::stringstream &ss) const override;

    int lookup_req(const std::string &appl_name, std::string *dst_node,
                   const std::string &preferred, uint32_t cookie) override;
    int appl_register(const struct rl_kmsg_appl_register *req) override;
    int rib_handler(const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
                    std::shared_ptr<Neighbor> const &neigh,
                    rlm_addr_t src_addr) override;
    int sync_neigh(const std::shared_ptr<NeighFlow> &nf,
                   unsigned int limit) const override;
    int neighs_refresh(size_t limit) override;

    /* Helper function shared with CentralizedFaultTolerantDFT::Replica. */
    void mod_table(const gpb::DFTEntry &e, bool add, gpb::DFTSlice *added,
                   gpb::DFTSlice *removed);
};

int
FullyReplicatedDFT::lookup_req(const std::string &appl_name,
                               std::string *dst_node,
                               const std::string &preferred, uint32_t cookie)
{
    /* Fetch all entries that hold 'appl_name'. */
    auto range = dft_table.equal_range(appl_name);
    int d;

    d = distance(range.first, range.second);

    if (d == 0) {
        /* No entry. */
        return -1;
    }

    auto mit = range.first;

    if (d > 1) {
        if (!preferred.empty()) {
            /* Only accept the preferred address. */

            for (; mit != range.second; mit++) {
                if (mit->second->ipcp_name() == preferred) {
                    break;
                }
            }
        } else {
            /* Load balance by selecting an entry based on
             * the cookie value. */
            cookie %= d;
            while (cookie > 0 && mit != range.second) {
                mit++;
                cookie--;
            }
        }

        assert(mit != range.second);
    }

    *dst_node = mit->second->ipcp_name();

    return 0;
}

int
FullyReplicatedDFT::appl_register(const struct rl_kmsg_appl_register *req)
{
    auto dft_entry = make_unique<gpb::DFTEntry>();
    multimap<string, std::unique_ptr<gpb::DFTEntry>>::iterator mit;
    string appl_name(req->appl_name);
    struct uipcp *uipcp = rib->uipcp;
    gpb::DFTSlice dft_slice;

    dft_entry->set_ipcp_name(rib->myname);
    dft_entry->set_allocated_appl_name(apname2gpb(appl_name));
    dft_entry->set_seqnum(seqnum_next++);

    /* Get all the entries for 'appl_name', and see if there
     * is an entry associated to this uipcp. */
    auto range = dft_table.equal_range(appl_name);
    for (mit = range.first; mit != range.second; mit++) {
        if (mit->second->ipcp_name() == rib->myname) {
            break;
        }
    }

    *dft_slice.add_entries() = *dft_entry;

    if (req->reg) {
        if (mit != range.second) { /* local collision */
            UPE(uipcp, "Application %s already registered on this uipcp\n",
                appl_name.c_str());
            return uipcp_appl_register_resp(uipcp, RLITE_ERR, req->hdr.event_id,
                                            req->appl_name);
        }

        if (req->reg) {
            /* Registration requires a response, while unregistrations doesn't.
             * Respond to the client before committing to the RIB, because the
             * response may fail. */
            int ret = uipcp_appl_register_resp(
                uipcp, RLITE_SUCC, req->hdr.event_id, req->appl_name);
            if (ret) {
                return ret;
            }
        }

        /* Insert the object into the RIB. */

        dft_table.insert(make_pair(appl_name, std::move(dft_entry)));
    } else {
        if (mit == range.second) {
            UPE(uipcp, "Application %s was not registered here\n",
                appl_name.c_str());
            return 0;
        }

        /* Remove from the RIB. */
        dft_table.erase(mit);
    }

    UPD(uipcp, "Application %s %sregistered\n", appl_name.c_str(),
        req->reg ? "" : "un");

    rib->neighs_sync_obj_all(req->reg != 0, ObjClass, TableName, &dft_slice);

    return 0;
}

/* Tries ot add or remove an entry 'e' from the DFT multimap. If not nullptr,
 * the entries added and/or removed are appended to 'added' and 'removed'
 * respectively. */
void
FullyReplicatedDFT::mod_table(const gpb::DFTEntry &e, bool add,
                              gpb::DFTSlice *added, gpb::DFTSlice *removed)
{
    string key = apname2string(e.appl_name());
    auto range = dft_table.equal_range(key);
    multimap<string, std::unique_ptr<gpb::DFTEntry>>::iterator mit;
    struct uipcp *uipcp = rib->uipcp;

    for (mit = range.first; mit != range.second; mit++) {
        if (mit->second->ipcp_name() == e.ipcp_name()) {
            break;
        }
    }

    if (add) {
        bool collision = (mit != range.second);

        if (!collision || e.seqnum() > mit->second->seqnum()) {
            if (collision) {
                /* Remove the collided entry. */
                if (removed) {
                    *removed->add_entries() = *mit->second;
                }
                dft_table.erase(mit);
            }
            dft_table.insert(make_pair(key, make_unique<gpb::DFTEntry>(e)));
            if (added) {
                *added->add_entries() = e;
            }
            UPD(uipcp, "DFT entry %s --> %s %s remotely\n", key.c_str(),
                e.ipcp_name().c_str(), (collision ? "updated" : "added"));
        }

    } else {
        if (mit == range.second) {
            UPI(uipcp, "DFT entry does not exist\n");
        } else {
            dft_table.erase(mit);
            if (removed) {
                *removed->add_entries() = e;
            }
            UPD(uipcp, "DFT entry %s --> %s removed remotely\n", key.c_str(),
                e.ipcp_name().c_str());
        }
    }
}

int
FullyReplicatedDFT::rib_handler(const CDAPMessage *rm,
                                std::shared_ptr<NeighFlow> const &nf,
                                std::shared_ptr<Neighbor> const &neigh,
                                rlm_addr_t src_addr)
{
    struct uipcp *uipcp = rib->uipcp;
    const char *objbuf;
    size_t objlen;
    bool add = true;

    if (rm->op_code != gpb::M_CREATE && rm->op_code != gpb::M_DELETE) {
        UPE(uipcp, "M_CREATE or M_DELETE expected\n");
        return 0;
    }

    if (rm->op_code == gpb::M_DELETE) {
        add = false;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(uipcp, "M_START does not contain a nested message\n");
        abort();
        return 0;
    }

    gpb::DFTSlice dft_slice;
    gpb::DFTSlice prop_dft_add, prop_dft_del;

    dft_slice.ParseFromArray(objbuf, objlen);
    for (const gpb::DFTEntry &e : dft_slice.entries()) {
        mod_table(e, add, &prop_dft_add, &prop_dft_del);
    }

    /* Propagate the DFT entries update to the other neighbors,
     * except for who told us. */
    if (prop_dft_add.entries_size() > 0) {
        rib->neighs_sync_obj_excluding(neigh, true, ObjClass, TableName,
                                       &prop_dft_add);
    }

    if (prop_dft_del.entries_size() > 0) {
        rib->neighs_sync_obj_excluding(neigh, false, ObjClass, TableName,
                                       &prop_dft_del);
    }

    return 0;
}

void
FullyReplicatedDFT::dump(stringstream &ss) const
{
    ss << "Directory Forwarding Table:" << endl;
    for (const auto &kve : dft_table) {
        const auto &entry = kve.second;

        ss << "    Application: " << apname2string(entry->appl_name())
           << ", Remote node: " << entry->ipcp_name()
           << ", Seqnum: " << entry->seqnum() << endl;
    }

    ss << endl;
}

int
FullyReplicatedDFT::sync_neigh(const std::shared_ptr<NeighFlow> &nf,
                               unsigned int limit) const
{
    int ret = 0;

    for (auto eit = dft_table.begin(); eit != dft_table.end();) {
        gpb::DFTSlice dft_slice;

        while (dft_slice.entries_size() < static_cast<int>(limit) &&
               eit != dft_table.end()) {
            *dft_slice.add_entries() = *eit->second;
            eit++;
        }

        ret |= nf->sync_obj(true, ObjClass, TableName, &dft_slice);
    }

    return ret;
}

/* Propagate local entries (i.e. the ones corresponding to locally
 * registered applications) to all our neighbors. */
int
FullyReplicatedDFT::neighs_refresh(size_t limit)
{
    int ret = 0;

    for (auto eit = dft_table.begin(); eit != dft_table.end();) {
        gpb::DFTSlice dft_slice;

        while (dft_slice.entries_size() < static_cast<int>(limit) &&
               eit != dft_table.end()) {
            if (eit->second->ipcp_name() == rib->myname) { /* local */
                *dft_slice.add_entries() = *eit->second;
            }
            eit++;
        }

        if (dft_slice.entries_size()) {
            ret |=
                rib->neighs_sync_obj_all(true, ObjClass, TableName, &dft_slice);
        }
    }

    return ret;
}

/* The CeftReplica class extends the Raft state machine by providing
 * generic glue functionalities to (i) send and receive messages to DIF members
 * through CDAP; (ii) keep track of pending client requests; (iii) implement
 * the timers needed by Raft.
 * Specific centralized-fault-tolerant components should extend this class
 * implementing the access to the specific resource and reacting to CDAP
 * input messages. */
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
    struct PendingReq {
        gpb::OpCode op_code;
        std::string obj_name;
        std::string obj_class;
        int invoke_id;
        rlm_addr_t requestor_addr;
        PendingReq() = default;
        PendingReq(gpb::OpCode op, const std::string &oname,
                   const std::string &oclass, int iid, rlm_addr_t addr)
            : op_code(op),
              obj_name(oname),
              obj_class(oclass),
              invoke_id(iid),
              requestor_addr(addr)
        {
        }
    };

    std::unordered_map<raft::LogIndex, std::unique_ptr<PendingReq>> pending;

    static std::string ReqVoteObjClass;
    static std::string ReqVoteRespObjClass;
    static std::string AppendEntriesObjClass;
    static std::string AppendEntriesRespObjClass;

protected:
    UipcpRib *rib = nullptr;

public:
    CeftReplica(UipcpRib *rib, const std::string &smname,
                const raft::ReplicaId &myname, std::string logname,
                size_t cmd_size, const std::string rib_obj_name)
        : raft::RaftSM(smname, myname, logname, cmd_size, std::cerr, std::cout),
          CommandSize(cmd_size),
          RibObjName(rib_obj_name),
          rib(rib)
    {
    }

    int init(const std::list<raft::ReplicaId> &peers);
    int process_sm_output(raft::RaftSMOutput out);
    int process_timeout();
    int apply(raft::LogIndex index, const char *const serbuf) override final;
    int rib_handler(const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
                    std::shared_ptr<Neighbor> const &neigh,
                    rlm_addr_t src_addr);
    virtual int apply(const char *const serbuf) = 0;
    virtual int process_rib_msg(
        const CDAPMessage *rm, rlm_addr_t src_addr,
        std::vector<std::unique_ptr<char[]>> *commands) = 0;
};

std::string CeftReplica::ReqVoteObjClass           = "raft_rv";
std::string CeftReplica::ReqVoteRespObjClass       = "raft_rv_r";
std::string CeftReplica::AppendEntriesObjClass     = "raft_ae";
std::string CeftReplica::AppendEntriesRespObjClass = "raft_ae_r";

int
CeftReplica::init(const std::list<raft::ReplicaId> &peers)
{
    set_election_timeout(Msecs(1000), Msecs(2000));
    set_heartbeat_timeout(Msecs(100));
    set_verbosity(raft::RaftSM::kVerboseInfo);

    raft::RaftSMOutput out;
    if (RaftSM::init(peers, &out)) {
        UPE(rib->uipcp, "Failed to init Raft state machine for DFT\n");
        return -1;
    }
    UPI(rib->uipcp, "Raft replica initialized\n");
    return process_sm_output(std::move(out));
}
int
CeftReplica::process_sm_output(raft::RaftSMOutput out)
{
    int ret = 0;

    /* Convert raft protocol messages from the library format to the
     * gpb format. */
    for (auto &pair : out.output_messages) {
        raft::RaftMessage *msg = pair.second.get();
        const auto *rv  = dynamic_cast<const raft::RaftRequestVote *>(msg);
        const auto *rvr = dynamic_cast<const raft::RaftRequestVoteResp *>(msg);
        auto *ae        = dynamic_cast<raft::RaftAppendEntries *>(msg);
        const auto *aer =
            dynamic_cast<const raft::RaftAppendEntriesResp *>(msg);
        auto m = make_unique<CDAPMessage>();
        std::unique_ptr<::google::protobuf::MessageLite> obj;
        std::string obj_class;

        if (rv) {
            auto mm = make_unique<gpb::RaftRequestVote>();
            mm->set_term(rv->term);
            mm->set_candidate_id(rv->candidate_id);
            mm->set_last_log_index(rv->last_log_index);
            mm->set_last_log_term(rv->last_log_term);
            obj       = std::move(mm);
            obj_class = ReqVoteObjClass;
        } else if (rvr) {
            auto mm = make_unique<gpb::RaftRequestVoteResp>();
            mm->set_term(rvr->term);
            mm->set_vote_granted(rvr->vote_granted);
            obj       = std::move(mm);
            obj_class = ReqVoteRespObjClass;
        } else if (ae) {
            auto mm = make_unique<gpb::RaftAppendEntries>();
            mm->set_term(ae->term);
            mm->set_leader_id(ae->leader_id);
            mm->set_leader_commit(ae->leader_commit);
            mm->set_prev_log_index(ae->prev_log_index);
            mm->set_prev_log_term(ae->prev_log_term);
            for (const auto &p : ae->entries) {
                gpb::RaftLogEntry *ge = mm->add_entries();
                ge->set_term(p.first);
                ge->set_buffer(p.second.get(), CommandSize);
            }
            obj       = std::move(mm);
            obj_class = AppendEntriesObjClass;
        } else if (aer) {
            auto mm = make_unique<gpb::RaftAppendEntriesResp>();
            mm->set_term(aer->term);
            mm->set_follower_id(aer->follower_id);
            mm->set_log_index(aer->log_index);
            mm->set_success(aer->success);
            obj       = std::move(mm);
            obj_class = AppendEntriesRespObjClass;
        } else {
            assert(false);
        }

        m->m_write(obj_class, RibObjName);
        ret |=
            rib->send_to_dst_node(std::move(m), pair.first, obj.get(), nullptr);
    }

    /* Here we make an assumption about the raft library, that is one
     * and only one timer is active at all times; so for example if the
     * heartbeat timer is active, the leader election timer can't be active.
     * As a result we have just one 'timer' class member (Replica::timer).
     * We first look at Stop commands, and then at Restart commands; this is
     * needed to prevent Stop commands to cancel the effect of Restart ones. */
    for (const auto &cmd : out.timer_commands) {
        if (cmd.action == raft::RaftTimerAction::Stop) {
            timer      = nullptr;
            timer_type = raft::RaftTimerType::Invalid;
            /* We can break, as more Stop commands won't have any effect. */
            break;
        }
    }
    for (const auto &cmd : out.timer_commands) {
        if (cmd.action == raft::RaftTimerAction::Restart) {
            /* The following assertion will fail if our assumption about
             * the unicity of the timer is not true. */
            assert(timer == nullptr || timer_type == cmd.type);
            timer = make_unique<TimeoutEvent>(
                cmd.milliseconds, rib->uipcp, this,
                [](struct uipcp *uipcp, void *arg) {
                    auto replica = static_cast<CeftReplica *>(arg);
                    replica->timer->fired();
                    replica->process_timeout();
                });
            timer_type = cmd.type;
        }
    }

    return ret;
}

int
CeftReplica::process_timeout()
{
    std::lock_guard<std::mutex> guard(rib->mutex);
    raft::RaftSMOutput out;

    timer_expired(timer_type, &out);

    return process_sm_output(std::move(out));
}

/* Apply a command to the replicated state machine. We just pass the command
 * to the same multimap implementation used by the fully replicated DFT. */
int
CeftReplica::apply(raft::LogIndex index, const char *const serbuf)
{
    /* Invoke the actual implementation. */
    apply(serbuf);

    /* Send a response to the client. */
    auto mit = pending.find(index);
    if (mit != pending.end()) {
        auto m = make_unique<CDAPMessage>();

        m->op_code = (mit->second->op_code == gpb::M_WRITE) ? gpb::M_WRITE_R
                                                            : gpb::M_DELETE_R;
        m->obj_name  = mit->second->obj_name;
        m->obj_class = mit->second->obj_class;
        m->invoke_id = mit->second->invoke_id;
        rib->send_to_dst_addr(std::move(m), mit->second->requestor_addr);
        UPD(rib->uipcp,
            "Pending response for index %u sent to client %llu "
            "(invoke_id=%d)\n",
            index, (long long unsigned)mit->second->requestor_addr,
            mit->second->invoke_id);
        pending.erase(index);
    }

    return 0;
}

int
CeftReplica::rib_handler(const CDAPMessage *rm,
                         std::shared_ptr<NeighFlow> const &nf,
                         std::shared_ptr<Neighbor> const &neigh,
                         rlm_addr_t src_addr)
{
    struct uipcp *uipcp = rib->uipcp;
    const char *objbuf  = nullptr;
    raft::RaftSMOutput out;
    size_t objlen = 0;
    int ret;

    if (src_addr == RL_ADDR_NULL) {
        UPE(uipcp, "Source address not set\n");
        return 0;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf && (rm->obj_class == ReqVoteObjClass ||
                    rm->obj_class == ReqVoteRespObjClass ||
                    rm->obj_class == AppendEntriesObjClass ||
                    rm->obj_class == AppendEntriesRespObjClass)) {
        UPE(uipcp, "No object value found\n");
        return 0;
    }

    if (rm->obj_class == ReqVoteObjClass) {
        auto rv = make_unique<raft::RaftRequestVote>();

        gpb::RaftRequestVote mm;
        mm.ParseFromArray(objbuf, objlen);
        rv->term           = mm.term();
        rv->candidate_id   = mm.candidate_id();
        rv->last_log_index = mm.last_log_index();
        rv->last_log_term  = mm.last_log_term();
        ret                = request_vote_input(*rv, &out);

    } else if (rm->obj_class == ReqVoteRespObjClass) {
        auto rvr = make_unique<raft::RaftRequestVoteResp>();

        gpb::RaftRequestVoteResp mm;
        mm.ParseFromArray(objbuf, objlen);
        rvr->term         = mm.term();
        rvr->vote_granted = mm.vote_granted();
        ret               = request_vote_resp_input(*rvr, &out);

    } else if (rm->obj_class == AppendEntriesObjClass) {
        auto ae = make_unique<raft::RaftAppendEntries>();

        gpb::RaftAppendEntries mm;
        mm.ParseFromArray(objbuf, objlen);
        ae->term           = mm.term();
        ae->leader_id      = mm.leader_id();
        ae->leader_commit  = mm.leader_commit();
        ae->prev_log_index = mm.prev_log_index();
        ae->prev_log_term  = mm.prev_log_term();
        for (int i = 0; i < mm.entries_size(); i++) {
            size_t bufsize = mm.entries(i).buffer().size();
            auto bufcopy   = std::unique_ptr<char[]>(new char[bufsize]);
            memcpy(bufcopy.get(), mm.entries(i).buffer().data(), bufsize);
            ae->entries.push_back(
                std::make_pair(mm.entries(i).term(), std::move(bufcopy)));
        }
        ret = append_entries_input(*ae, &out);

    } else if (rm->obj_class == AppendEntriesRespObjClass) {
        auto aer = make_unique<raft::RaftAppendEntriesResp>();

        gpb::RaftAppendEntriesResp mm;
        mm.ParseFromArray(objbuf, objlen);
        aer->term        = mm.term();
        aer->follower_id = mm.follower_id();
        aer->log_index   = mm.log_index();
        aer->success     = mm.success();
        ret              = append_entries_resp_input(*aer, &out);
    } else {
        /* This is not a message belonging to the raft protocol. Forward it
         * to the underlying implementation. */
        vector<std::unique_ptr<char[]>> commands;

        process_rib_msg(rm, src_addr, &commands);

        /* Submit commands to the raft state machine, if any. */
        for (const auto &command : commands) {
            raft::LogIndex index;

            ret = submit(reinterpret_cast<const char *const>(command.get()),
                         &index, &out);
            if (ret) {
                UPE(uipcp, "Failed to submit command (%s) to the RaftSM\n",
                    rm->obj_class.c_str());
                continue;
            }
            pending[index] =
                make_unique<PendingReq>(rm->op_code, rm->obj_name,
                                        rm->obj_class, rm->invoke_id, src_addr);
        }
    }

    /* Complete raft processing. */
    return process_sm_output(std::move(out));
}

class CentralizedFaultTolerantDFT : public DFT {
    /* An instance of this class can be a state machine replica or it can just
     * be a client that will redirect requests to one of the replicas. */

    /* In case of state machine replica, a pointer to a Raft state
     * machine. */
    class Replica : public CeftReplica {
        /* The structure of a DFT command (i.e. a log entry for the Raft SM). */
        struct Command {
            char appl_name[32];
            char ipcp_name[31];
            uint8_t opcode;
            static constexpr uint8_t OpcodeSet = 1;
            static constexpr uint8_t OpcodeDel = 2;
        } __attribute__((packed));
        static_assert(sizeof(Command) == sizeof(Command::ipcp_name) +
                                             sizeof(Command::appl_name) +
                                             sizeof(Command::opcode),
                      "Invalid memory layout for class Replica::Command");

        /* State machine implementation. Just reuse the implementation of
         * a fully replicated DFT. */
        std::unique_ptr<FullyReplicatedDFT> impl;

        uint64_t seqnum_next = 1;

    public:
        Replica(CentralizedFaultTolerantDFT *dft)
            : CeftReplica(dft->rib, std::string("ceft-dft-") + dft->rib->myname,
                          dft->rib->myname,
                          std::string("/tmp/ceft-dft-") +
                              std::to_string(dft->rib->uipcp->id) +
                              std::string("-") + dft->rib->myname,
                          sizeof(Command), DFT::TableName),
              impl(make_unique<FullyReplicatedDFT>(dft->rib)){};
        int apply(const char *const serbuf) override;
        int process_rib_msg(
            const CDAPMessage *rm, rlm_addr_t src_addr,
            std::vector<std::unique_ptr<char[]>> *commands) override;
        int lookup_req(const std::string &appl_name, std::string *dst_node,
                       const std::string &preferred, uint32_t cookie)
        {
            return impl->lookup_req(appl_name, dst_node, preferred, cookie);
        }
        void dump(std::stringstream &ss) const { impl->dump(ss); };
    };
    std::unique_ptr<Replica> raft;

    /* In case of client, a pointer to client-side data structures. */
    class Client {
        UipcpRib *rib = nullptr;
        std::list<raft::ReplicaId> replicas;
        /* The leader, if we know who it is, otherwise the empty
         * string. */
        raft::ReplicaId leader_id;
        /* The replica that responded first to an M_READ, if any. */
        raft::ReplicaId reader_id;
        std::unique_ptr<TimeoutEvent> timer;

        struct PendingReq {
            gpb::OpCode op_code;
            std::string appl_name;
            raft::ReplicaId replica;
            uint32_t kevent_id;
            std::chrono::system_clock::time_point t;
            PendingReq() = default;
            PendingReq(gpb::OpCode op, const std::string &a,
                       const raft::ReplicaId &r, uint32_t event_id)
                : op_code(op), appl_name(a), replica(r), kevent_id(event_id)
            {
                t = std::chrono::system_clock::now() + Secs(3);
            }
        };
        std::unordered_map</*invoke_id*/ int, std::unique_ptr<PendingReq>>
            pending;
        uint64_t seqnum_next = 1;

        void mod_pending_timer();

    public:
        Client(CentralizedFaultTolerantDFT *dft,
               std::list<raft::ReplicaId> names)
            : rib(dft->rib), replicas(std::move(names))
        {
        }
        int lookup_req(const std::string &appl_name, std::string *dst_node,
                       const std::string &preferred, uint32_t cookie);
        int appl_register(const struct rl_kmsg_appl_register *req);
        int rib_handler(const CDAPMessage *rm,
                        std::shared_ptr<NeighFlow> const &nf,
                        std::shared_ptr<Neighbor> const &neigh,
                        rlm_addr_t src_addr);
        int process_timeout();

        /* For external hints. */
        void set_leader_id(const raft::ReplicaId &name)
        {
            leader_id = reader_id = name;
        }
    };
    std::unique_ptr<Client> client;

public:
    RL_NODEFAULT_NONCOPIABLE(CentralizedFaultTolerantDFT);
    CentralizedFaultTolerantDFT(UipcpRib *_ur) : DFT(_ur) {}
    int reconfigure() override;
    void dump(std::stringstream &ss) const override
    {
        if (raft) {
            raft->dump(ss);
        } else {
            ss << "Directory Forwarding Table: not available locally" << endl
               << endl;
        }
    }

    int lookup_req(const std::string &appl_name, std::string *dst_node,
                   const std::string &preferred, uint32_t cookie) override
    {
        if (raft) {
            return raft->lookup_req(appl_name, dst_node, preferred, cookie);
        }
        return client->lookup_req(appl_name, dst_node, preferred, cookie);
    }
    int appl_register(const struct rl_kmsg_appl_register *req) override
    {
        if (raft) {
            /* We may be the leader or a follower, but here we can behave as as
             * any client to improve code reuse. We also set the leader, since
             * we know it.
             */
            client->set_leader_id(raft->leader_name());
        }
        return client->appl_register(req);
    }
    int rib_handler(const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
                    std::shared_ptr<Neighbor> const &neigh, rlm_addr_t src_addr)
    {
        if (!raft || (rm->obj_class == ObjClass && rm->is_response())) {
            /* We may be a replica (raft != nullptr), but if this is a response
             * to a request done by us with the role of simple clients we
             * forward it to the client handler. */
            return client->rib_handler(rm, nf, neigh, src_addr);
        }

        return raft->rib_handler(rm, nf, neigh, src_addr);
    }
};

int
CentralizedFaultTolerantDFT::reconfigure()
{
    list<raft::ReplicaId> peers;
    string replicas;

    replicas = rib->get_param_value<std::string>(DFT::Prefix, "replicas");
    if (replicas.empty()) {
        UPW(rib->uipcp, "replicas param not configured\n");
    } else {
        UPD(rib->uipcp, "replicas = %s\n", replicas.c_str());
    }
    peers = strsplit(replicas, ',');

    /* Create the client anyway. */
    client = make_unique<Client>(this, peers);
    UPI(rib->uipcp, "Client initialized\n");

    /* See if I'm also one of the replicas. */
    auto it = peers.begin();
    for (; it != peers.end(); it++) {
        if (*it == rib->myname) {
            /* I'm one of the replicas. Create a Raft state machine and
             * initialize it. */
            raft = make_unique<Replica>(this);
            peers.erase(it); /* remove myself */

            return raft->init(peers);
        }
    }

    return 0;
}

/* Process the expired entries and rearm the timer according to the
 * oldest pending request (i.e. the next one that is expiring); or
 * stop it if there are no pending requests. */
void
CentralizedFaultTolerantDFT::Client::mod_pending_timer()
{
    auto t_min = std::chrono::system_clock::time_point::max();
    auto now   = std::chrono::system_clock::now();

    for (auto mit = pending.begin(); mit != pending.end();) {
        if (mit->second->t <= now) {
            /* This request has expired. */
            UPW(rib->uipcp, "DFT '%s' request for name '%s' timed out\n",
                CDAPMessage::opcode_repr(mit->second->op_code).c_str(),
                mit->second->appl_name.c_str());
            if (mit->second->replica == leader_id) {
                /* We got a timeout on the leader, let's forget about it. */
                UPD(rib->uipcp, "Forgetting about raft leader %s\n",
                    leader_id.c_str());
                leader_id.clear();
            } else if (mit->second->replica == reader_id) {
                /* We got a timeout on the selected reader,
                 * let's forget about it. */
                UPD(rib->uipcp, "Forgetting about selected reader %s\n",
                    reader_id.c_str());
                reader_id.clear();
            }
            mit = pending.erase(mit);
        } else {
            if (mit->second->t < t_min) {
                /* Update the oldest request. */
                t_min = mit->second->t;
            }
            ++mit;
        }
    }

    /* Update the timer. */
    if (t_min == std::chrono::system_clock::time_point::max()) {
        timer = nullptr;
    } else {
        timer = make_unique<TimeoutEvent>(
            std::chrono::duration_cast<Msecs>(t_min - now), rib->uipcp, this,
            [](struct uipcp *uipcp, void *arg) {
                auto cli =
                    static_cast<CentralizedFaultTolerantDFT::Client *>(arg);
                cli->timer->fired();
                cli->process_timeout();
            });
    }
}

int
CentralizedFaultTolerantDFT::Client::lookup_req(const std::string &appl_name,
                                                std::string *dst_node,
                                                const std::string &preferred,
                                                uint32_t cookie)
{
    /* Prepare an M_READ for a read operation. If we have a selected reader,
     * we send it to the reader only; otherwise we send it to all the replicas.
     */
    for (const auto &r : replicas) {
        if (reader_id.empty() || r == reader_id) {
            auto m = make_unique<CDAPMessage>();
            gpb::OpCode op_code;
            int invoke_id;
            int ret;

            m->m_read(ObjClass, TableName + "/" + appl_name);
            op_code = m->op_code;

            m->invoke_id = invoke_id = rib->invoke_id_mgr.get_invoke_id();
            pending[invoke_id] =
                make_unique<PendingReq>(op_code, appl_name, r, 0);

            ret = rib->send_to_dst_node(std::move(m), r, nullptr, nullptr);
            if (ret) {
                pending.erase(invoke_id);
                return ret;
            }
        }
    }

    mod_pending_timer();

    UPI(rib->uipcp, "Read request for '%s' issued\n", appl_name.c_str());

    /* Inform the caller that we issued the request, but the
     * response will come later. */
    *dst_node = std::string();

    return 0;
}

int
CentralizedFaultTolerantDFT::Client::appl_register(
    const struct rl_kmsg_appl_register *req)
{
    string appl_name(req->appl_name);

    /* Prepare an M_WRITE or M_DELETE message for a write/delete operation.
     * If we know who is the leader, we send it to the leader only; otherwise
     * we send it to all the replicas. */
    for (const auto &r : replicas) {
        if (leader_id.empty() || r == leader_id) {
            auto m = make_unique<CDAPMessage>();
            gpb::OpCode op_code;
            gpb::DFTEntry dft_entry;
            int invoke_id;
            int ret;

            if (req->reg) {
                m->m_write(ObjClass, TableName);
            } else {
                m->m_delete(ObjClass, TableName);
            }
            op_code = m->op_code;
            dft_entry.set_ipcp_name(rib->myname);
            dft_entry.set_allocated_appl_name(apname2gpb(appl_name));
            dft_entry.set_seqnum(seqnum_next++);

            /* Set the 'pending' map before sending, in case we are sending to
             * ourselves (and so we wouldn't find the entry in the map).*/
            m->invoke_id = invoke_id = rib->invoke_id_mgr.get_invoke_id();
            pending[invoke_id] = make_unique<PendingReq>(op_code, appl_name, r,
                                                         req->hdr.event_id);
            ret = rib->send_to_dst_node(std::move(m), r, &dft_entry, nullptr);
            if (ret) {
                pending.erase(invoke_id);
                return ret;
            }
        }
    }

    mod_pending_timer();

    if (req->reg) {
        UPD(rib->uipcp, "Write request '%s <= %llu' issued\n",
            appl_name.c_str(), (long long unsigned)rib->myaddr);
    } else {
        UPD(rib->uipcp, "Write request 'delete %s' issued\n",
            appl_name.c_str());
    }

    return 0;
}

int
CentralizedFaultTolerantDFT::Client::process_timeout()
{
    std::lock_guard<std::mutex> guard(rib->mutex);

    mod_pending_timer();

    return 0;
}

int
CentralizedFaultTolerantDFT::Client::rib_handler(
    const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
    std::shared_ptr<Neighbor> const &neigh, rlm_addr_t src_addr)
{
    struct uipcp *uipcp = rib->uipcp;

    /* We expect a M_WRITE_R, M_DELETE_R or M_READ_R, corresponding an
     * M_WRITE/M_DELETE sent by Client::appl_register() or an M_READ sent by
     * Client::lookup_req(). */
    if (rm->op_code != gpb::M_WRITE_R && rm->op_code != gpb::M_DELETE_R &&
        rm->op_code != gpb::M_READ_R) {
        UPE(uipcp, "Cannot handle opcode %d\n", rm->op_code);
        return 0;
    }

    /* Lookup rm->invoke_id in the pending map and erase it. Lookup
     * may fail if we receive multiple responses (but not for the
     * first response). */
    auto pi = pending.find(rm->invoke_id);
    if (pi == pending.end()) {
        UPW(uipcp, "Cannot find pending request with invoke id %d\n",
            rm->invoke_id);
        return 0;
    }

    /* Check that rm->op_code is consistent with the pending request. */
    if (pi->second->op_code + 1 != rm->op_code) {
        UPE(uipcp, "Opcode mismatch for request with invoke id %d\n",
            rm->invoke_id);
        pending.erase(pi);
        return 0;
    }

    if (rm->op_code == gpb::M_READ_R) {
        /* The first reader that answers becomes our selected reader. */
        if (reader_id.empty()) {
            reader_id = pi->second->replica;
            UPD(uipcp, "Selected reader: %s\n", reader_id.c_str());
        }
    } else {
        /* We assume it was the leader to answer. So now we know who the
         * leader is. */
        if (leader_id.empty()) {
            leader_id = pi->second->replica;
            UPD(uipcp, "Raft leader discovered: %s\n", leader_id.c_str());
        }
    }

    switch (rm->op_code) {
    case gpb::M_WRITE_R:
    case gpb::M_DELETE_R:
        if (rm->op_code == gpb::M_WRITE_R) {
            /* Registrations need a response. */
            uipcp_appl_register_resp(uipcp, rm->result ? RLITE_ERR : RLITE_SUCC,
                                     pi->second->kevent_id,
                                     pi->second->appl_name.c_str());
        }
        UPD(uipcp, "Application %s %sregistration %s\n",
            pi->second->appl_name.c_str(),
            rm->op_code == gpb::M_WRITE_R ? "" : "un",
            rm->result ? "failed" : "was successful");
        break;
    case gpb::M_READ_R: {
        std::string remote_node;

        if (rm->result) {
            UPD(uipcp, "Lookup of name '%s' failed remotely [%s]\n",
                pi->second->appl_name.c_str(), rm->result_reason.c_str());
        } else {
            rm->get_obj_value(remote_node);
            UPD(uipcp, "Lookup of name '%s' resolved to node '%s'\n",
                pi->second->appl_name.c_str(), remote_node.c_str());
        }
        rib->dft_lookup_resolved(pi->second->appl_name, remote_node);
        break;
    }
    default:
        assert(false);
    }
    pending.erase(pi);
    mod_pending_timer();

    return 0;
}

/* Apply a command to the replicated state machine. We just pass the command
 * to the same multimap implementation used by the fully replicated DFT. */
int
CentralizedFaultTolerantDFT::Replica::apply(const char *const serbuf)
{
    auto c = reinterpret_cast<const Command *const>(serbuf);
    gpb::DFTEntry e;

    e.set_ipcp_name(c->ipcp_name);
    e.set_allocated_appl_name(apname2gpb(c->appl_name));
    e.set_seqnum(seqnum_next++);
    assert(c->opcode == Command::OpcodeSet || c->opcode == Command::OpcodeDel);
    impl->mod_table(e, c->opcode == Command::OpcodeSet, nullptr, nullptr);

    return 0;
}

int
CentralizedFaultTolerantDFT::Replica::process_rib_msg(
    const CDAPMessage *rm, rlm_addr_t src_addr,
    std::vector<std::unique_ptr<char[]>> *commands)
{
    struct uipcp *uipcp = rib->uipcp;
    const char *objbuf  = nullptr;
    size_t objlen       = 0;

    if (rm->obj_class != ObjClass) {
        UPE(uipcp, "Unexpected object class '%s'\n", rm->obj_class.c_str());
        return 0;
    }

    /* We expect an obj_value if this is not a DFT read request. */
    if (rm->op_code != gpb::M_READ) {
        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            UPE(uipcp, "No object value found\n");
            return 0;
        }
    }

    if (!leader() && rm->op_code != gpb::M_READ) {
        /* We are not the leader and this is not a read request. We
         * need to deny the request to preserve consistency. */
        UPD(uipcp, "Ignoring request, let the leader answer\n");
        return 0;
    }

    /* Either we are the leader (so we can go ahead and serve the request),
     * or this is a read request that we can serve because it's ok to be
     * eventually consistent. */

    if (rm->op_code == gpb::M_WRITE || rm->op_code == gpb::M_DELETE) {
        /* We received an M_WRITE or M_DELETE as sent by
         * Client::appl_register(). We are the leader. Let's submit the
         * request to the Raft state machine. */
        gpb::DFTEntry dft_entry;
        string appl_name;
        auto cbuf  = std::unique_ptr<char[]>(new char[sizeof(Command)]);
        Command *c = reinterpret_cast<Command *>(cbuf.get());

        dft_entry.ParseFromArray(objbuf, objlen);
        appl_name = apname2string(dft_entry.appl_name());
        /* Fill in the command struct (already serialized). */
        strncpy(c->ipcp_name, dft_entry.ipcp_name().c_str(),
                sizeof(c->ipcp_name));
        strncpy(c->appl_name, appl_name.c_str(), sizeof(c->appl_name));
        c->opcode = rm->op_code == gpb::M_WRITE ? Command::OpcodeSet
                                                : Command::OpcodeDel;

        commands->push_back(std::move(cbuf));
    } else if (rm->op_code == gpb::M_READ) {
        /* We received an an M_READ sent by Client::lookup_req().
         * Recover the application name, look it up in the DFT and
         * reply. */
        auto m = make_unique<CDAPMessage>();
        std::string remote_node;
        string appl_name;
        int ret;

        appl_name = rm->obj_name.substr(rm->obj_name.rfind("/") + 1);
        ret       = impl->lookup_req(appl_name, &remote_node,
                               /*preferred=*/std::string(), /*cookie=*/0);
        m->m_read_r(rm->obj_class, rm->obj_name, /*obj_inst=*/0,
                    /*result=*/ret ? -1 : 0,
                    /*result_reason=*/ret ? "No match found" : string());
        m->invoke_id = rm->invoke_id;
        m->set_obj_value(remote_node);
        rib->send_to_dst_addr(std::move(m), src_addr);
    } else {
        UPE(uipcp, "M_WRITE(dft) or M_DELETE(dft) expected\n");
        return 0;
    }

    return 0;
}

void
UipcpRib::dft_lib_init()
{
    available_policies[DFT::Prefix].insert(PolicyBuilder(
        "fully-replicated",
        [](UipcpRib *rib) { rib->dft = make_unique<FullyReplicatedDFT>(rib); },
        {DFT::TableName}));
    available_policies[DFT::Prefix].insert(PolicyBuilder(
        "centralized-fault-tolerant",
        [](UipcpRib *rib) {
            rib->dft = make_unique<CentralizedFaultTolerantDFT>(rib);
        },
        {DFT::TableName}));
}

} // namespace Uipcps
