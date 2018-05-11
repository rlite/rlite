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

#include <vector>
#include <map>

#include "uipcp-normal-ceft.hpp"
#include "Raft.pb.h"

namespace Uipcps {

std::string CeftReplica::ReqVoteObjClass           = "raft_rv";
std::string CeftReplica::ReqVoteRespObjClass       = "raft_rv_r";
std::string CeftReplica::AppendEntriesObjClass     = "raft_ae";
std::string CeftReplica::AppendEntriesRespObjClass = "raft_ae_r";

int
CeftReplica::init(const std::list<raft::ReplicaId> &peers)
{
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
    std::unique_ptr<CDAPMessage> rm;

    /* Check if this is associated to a client request. This happens if we
     * were the leader for this log entry. */
    auto mit = pending.find(index);
    if (mit != pending.end()) {
        rm = std::move(mit->second->m);
    }

    /* Invoke the actual state machine update. This may modify the response (if
     * any) with the result of the update. */
    apply(serbuf, rm.get());

    if (mit != pending.end()) {
        /* Send the response to the client and flush the pending response. */
        int invoke_id = rm->invoke_id;
        rib->send_to_dst_addr(std::move(rm), mit->second->requestor_addr);
        UPD(rib->uipcp,
            "Pending response for index %u sent to client %llu "
            "(invoke_id=%d)\n",
            index, (long long unsigned)mit->second->requestor_addr, invoke_id);
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
        std::vector<CommandToSubmit> commands;

        replica_process_rib_msg(rm, src_addr, &commands);

        /* Submit commands to the raft state machine, if any. */
        for (auto &command : commands) {
            raft::LogIndex index;

            ret =
                submit(reinterpret_cast<const char *const>(command.first.get()),
                       &index, &out);
            if (ret) {
                UPE(uipcp, "Failed to submit command (%s) to the RaftSM\n",
                    rm->obj_class.c_str());
                continue;
            }
            pending[index] =
                make_unique<PendingResp>(std::move(command.second), src_addr);
        }
    }

    /* Complete raft processing. */
    return process_sm_output(std::move(out));
}

int
CeftClient::process_timeout()
{
    std::lock_guard<std::mutex> guard(rib->mutex);

    mod_pending_timer();

    return 0;
}

/* Process the expired entries and rearm the timer according to the
 * oldest pending request (i.e. the next one that is expiring); or
 * stop it if there are no pending requests. */
void
CeftClient::mod_pending_timer()
{
    auto t_min = std::chrono::system_clock::time_point::max();
    auto now   = std::chrono::system_clock::now();

    for (auto mit = pending.begin(); mit != pending.end();) {
        if (mit->second->t <= now) {
            /* This request has expired. */
            UPW(rib->uipcp, "'%s' request to replica '%s' timed out\n",
                CDAPMessage::opcode_repr(mit->second->op_code).c_str(),
                mit->second->replica.c_str());
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
                auto cli = static_cast<CeftClient *>(arg);
                cli->timer->fired();
                cli->process_timeout();
            });
    }
}

int
CeftClient::send_to_replicas(std::unique_ptr<CDAPMessage> m,
                             std::unique_ptr<PendingReq> pr, OpSemantics sem)
{
    const raft::ReplicaId &selected_id =
        (sem == OpSemantics::Get) ? reader_id : leader_id;

    /* If we have a selected for this operation (leader or selected reader), we
     * send it to that replica only; otherwise we send it to all the replicas.
     */
    for (const auto &r : replicas) {
        if (selected_id.empty() || r == selected_id) {
            auto mc  = make_unique<CDAPMessage>(*m);
            auto prc = pr->clone();
            int invoke_id;
            int ret;

            /* Set the 'pending' map before sending, in case we are sending to
             * ourselves (and so we wouldn't find the entry in the map).*/
            mc->invoke_id = invoke_id = rib->invoke_id_mgr.get_invoke_id();
            prc->replica              = r;
            pending[invoke_id]        = std::move(prc);
            ret = rib->send_to_dst_node(std::move(mc), r, nullptr, nullptr);
            if (ret) {
                pending.erase(invoke_id);
                return ret;
            }
        }
    }

    mod_pending_timer();

    return 0;
}

int
CeftClient::rib_handler(const CDAPMessage *rm,
                        std::shared_ptr<NeighFlow> const &nf,
                        std::shared_ptr<Neighbor> const &neigh,
                        rlm_addr_t src_addr)
{
    struct uipcp *uipcp = rib->uipcp;

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
    if (rm->op_code != pi->second->op_code + 1) {
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

    /* Handle the message to the underlying implementation. */
    int ret = client_process_rib_msg(rm, pi->second.get(), src_addr);
    pending.erase(pi);
    mod_pending_timer();

    return ret;
}

} // namespace Uipcps
