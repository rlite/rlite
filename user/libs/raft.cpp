/*
 * An implementation of the Raft protocol.
 *
 * Copyright (C) 2017 Nextworks
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

#include "rlite/raft.hpp"
#include <cassert>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "rlite/cpputils.hpp"

using namespace std;

int
RaftSM::init(const list<ReplicaId> peers, RaftSMOutput *out)
{
    /* If logfile does not exists it means that this is the first time
     * this replica boots. */
    bool first_boot              = !ifstream(logfilename).good();
    std::ios_base::openmode mode = ios::in | ios::out | ios::binary;
    int ret;

    if (check_output_arg(out)) {
        return -1;
    }

    if (first_boot) {
        mode |= ios::trunc;
    } else {
        mode |= ios::ate;
    }

    logfile.open(logfilename, mode);
    if (logfile.fail()) {
        IOS_ERR() << "Failed to open logfile '" << logfilename
                  << "': " << strerror(errno) << endl;
        return -1;
    }
    if (first_boot) {
        char null[kLogVotedForSize];

        /* Initialize the log header. Write an 4 byte magic
         * number, a 4 bytes current_term and a null voted_for. */
        if ((ret = log_u32_write(kLogMagicOfs, kLogMagicNumber))) {
            return ret;
        }
        if ((ret = log_u32_write(kLogCurrentTermOfs, 0))) {
            return ret;
        }
        memset(null, 0, sizeof(null));
        if ((ret = log_buf_write(kLogVotedForOfs, null, kLogVotedForSize))) {
            return ret;
        }
        last_log_index = 0;
        IOS_INF() << "Raft log initialized on first boot" << endl;

    } else {
        char id_buf[kLogVotedForSize];
        long log_size;

        /* Get pointer is at the end because of ios::ate. We can then compute
         * the last log entry. */
        log_size = static_cast<long>(logfile.tellg()) - kLogEntriesOfs;
        if (log_size < 0 || log_size % log_entry_size != 0) {
            IOS_ERR() << "Log size " << log_size << " is invalid" << endl;
            return -1;
        }
        last_log_index = log_size / log_entry_size;

        /* Check the magic number and load current term and current
         * voted candidate. */
        if ((ret = magic_check())) {
            IOS_ERR() << "Log content is corrupted or invalid" << endl;
            return ret;
        }
        if ((ret = log_u32_read(kLogCurrentTermOfs, &current_term))) {
            return ret;
        }
        if ((ret = log_buf_read(kLogVotedForOfs, id_buf, kLogVotedForSize))) {
            return ret;
        }
        /* Check that the 'voted_for' field on disk is null terminated. */
        auto buf_is_null_terminated = [](const char *buf, size_t len) -> bool {
            for (size_t i = 0; i < len; i++) {
                if (buf[i] == '\0') {
                    return true;
                }
            }
            return false;
        };
        if (!buf_is_null_terminated(id_buf, kLogVotedForSize)) {
            IOS_ERR() << "Log contains an invalid voted_for field" << endl;
            return -1;
        }
        voted_for               = string(id_buf);
        auto voted_for_is_valid = [this, peers]() -> bool {
            if (voted_for.empty()) {
                return true;
            }
            if (voted_for == local_id) {
                return true;
            }
            for (const auto &peer : peers) {
                if (voted_for == peer) {
                    return true;
                }
            }
            return false;
        };
        if (!voted_for_is_valid()) {
            IOS_ERR() << "Log contains a voted_for identifier that does not "
                         "match any replica"
                      << endl;
            return -1;
        }
        IOS_INF() << "Raft log recovered" << endl;
    }

    for (const auto &rid : peers) {
        servers[rid].match_index = 0;
        servers[rid].next_index  = last_log_index + 1;
    }

    /* Initialization is complete, we can set the election timer and return to
     * the caller. */
    out->timer_commands.push_back(RaftTimerCmd(this, RaftTimerType::Election,
                                               RaftTimerAction::Restart,
                                               rand_int_in_range(200, 500)));

    return 0;
}

void
RaftSM::shutdown()
{
    if (remove(logfilename.c_str())) {
        IOS_ERR() << "Failed to remove log file '" << logfilename
                  << "': " << strerror(errno) << endl;
    }
}

RaftSM::~RaftSM()
{
    if (logfile.is_open()) {
        logfile.close();
    }
}

int
RaftSM::log_disk_flush()
{
    int ret;
    int fd;

    logfile << std::flush;

    fd = open(logfilename.c_str(), O_APPEND);
    if (fd < 0) {
        IOS_ERR() << "Failed to open logfile for disk flush ["
                  << strerror(errno) << "]" << endl;
        return fd;
    }

    if ((ret = fdatasync(fd))) {
        IOS_ERR() << "Failed to flush logfile contents to disk ["
                  << strerror(errno) << "]" << endl;
        return ret;
    }

    return 0;
}

int
RaftSM::log_u32_write(unsigned long pos, uint32_t val)
{
    logfile.seekp(pos);
    if (logfile.fail()) {
        IOS_ERR() << "Failed to seek log at position " << pos << endl;
        return -1;
    }
    logfile.write(reinterpret_cast<const char *>(&val), sizeof(val));
    if (logfile.fail()) {
        IOS_ERR() << "Failed to write u32 at position " << pos << endl;
        return -1;
    }
    return log_disk_flush();
}

int
RaftSM::log_u32_read(unsigned long pos, uint32_t *val)
{
    logfile.seekg(pos);
    if (logfile.fail() || logfile.eof()) {
        IOS_ERR() << "Failed to seek log at position " << pos << endl;
        return -1;
    }
    logfile.read(reinterpret_cast<char *>(val), sizeof(*val));
    if (logfile.fail() || logfile.eof()) {
        IOS_ERR() << "Failed to read u32 at position " << pos << endl;
        return -1;
    }
    return 0;
}

int
RaftSM::magic_check()
{
    uint32_t magic = 0;

    if (log_u32_read(kLogMagicOfs, &magic)) {
        return -1;
    }
    return (magic != kLogMagicNumber) ? -1 : 0;
}

int
RaftSM::log_buf_write(unsigned long pos, const char *buf, size_t len)
{
    logfile.seekp(pos);
    if (logfile.fail()) {
        IOS_ERR() << "Failed to seek log at position " << pos << endl;
        return -1;
    }
    logfile.write(buf, len);
    if (logfile.fail()) {
        IOS_ERR() << "Failed to write " << len << " bytes at position " << pos
                  << endl;
        return -1;
    }
    return log_disk_flush();
}

int
RaftSM::log_buf_read(unsigned long pos, char *buf, size_t len)
{
    logfile.seekg(pos);
    if (logfile.fail() || logfile.eof()) {
        IOS_ERR() << "Failed to seek log at position " << pos << endl;
        return -1;
    }
    logfile.read(buf, len);
    if (logfile.fail() || logfile.eof()) {
        IOS_ERR() << "Failed to read " << len << " bytes at position " << pos
                  << endl;
        return -1;
    }
    return 0;
}

int
RaftSM::rand_int_in_range(int left, int right)
{
    assert(right > left);
    return left + (rand() % (right - left));
}

std::string
RaftSM::state_repr(RaftState st) const
{
    switch (st) {
    case RaftState::Follower:
        return "Follower";
    case RaftState::Candidate:
        return "Candidate";
    case RaftState::Leader:
        return "Leader";
    }

    assert(false);

    return "Unknown";
}

void
RaftSM::switch_state(RaftState next)
{
    if (state == next) {
        return; /* nothing to do */
    }
    IOS_INF() << "switching " << state_repr(state) << " --> "
              << state_repr(next) << endl;
    state = next;
}

int
RaftSM::check_output_arg(RaftSMOutput *out)
{
    if (out == nullptr) {
        IOS_ERR() << "Invalid output parameter" << endl;
        return -1;
    }

    return 0;
}

/* Updates 'voted_for' persistent data. May be called with an empty string
 * to reset voting state. */
int
RaftSM::vote_for_candidate(ReplicaId candidate)
{
    if (voted_for != candidate) {
        char buf_id[kLogVotedForSize];
        int ret;

        voted_for = candidate;
        snprintf(buf_id, sizeof(buf_id), "%s", voted_for.c_str());
        if ((ret = log_buf_write(kLogVotedForOfs, buf_id, sizeof(buf_id)))) {
            return ret;
        }
    }

    return 0;
}

unsigned int
RaftSM::quorum() const
{
    double q = 0.5 * (servers.size() + 1);
    return static_cast<unsigned int>(ceil(q));
}

/* Switch back to follower state, resetting the voting state and
 * restarting the election timer. */
int
RaftSM::back_to_follower(RaftSMOutput *out)
{
    int ret;

    votes_collected = 0;
    if ((ret = vote_for_candidate(string()))) {
        return ret;
    }
    switch_state(RaftState::Follower);
    out->timer_commands.push_back(RaftTimerCmd(this, RaftTimerType::Election,
                                               RaftTimerAction::Restart,
                                               rand_int_in_range(200, 500)));
    /* Also stop the heartbeat timer, in case we were leader. */
    out->timer_commands.push_back(
        RaftTimerCmd(this, RaftTimerType::HeartBeat, RaftTimerAction::Stop));

    return 0;
}

/* Called on any input message to check if our term is outdated. */
int
RaftSM::catch_up_term(Term term, RaftSMOutput *out)
{
    int ret;

    if (term <= current_term) {
        return 0; /* nothing to do */
    }

    /* Our term is outdated. Updated it and become a follower. */
    IOS_INF() << "Update current term " << current_term << " --> " << term
              << endl;
    current_term = term;
    if ((ret = log_u32_write(kLogCurrentTermOfs, current_term))) {
        return ret;
    }
    if ((ret = back_to_follower(out))) {
        return ret;
    }

    return 1;
}

int
RaftSM::log_entry_get_term(LogIndex index, Term *term)
{
    if (index == 0) {
        *term = 0;
        return 0;
    }

    if (index > last_log_index) {
        return 1; /* no such entry */
    }

    return log_u32_read(kLogEntriesOfs + (index - 1) * log_entry_size, term);
}

/* Prepare a RaftAppendEntries message with the given 'entry. If 'entry' is
 * nullptr we prepare an heartbeat message. */
int
RaftSM::prepare_append_entries(const Term term, const char *const serbuf,
                               RaftSMOutput *out)
{
    for (const auto &kv : servers) {
        auto msg            = make_unique<RaftAppendEntries>();
        msg->term           = current_term;
        msg->leader_id      = local_id;
        msg->leader_commit  = commit_index;
        msg->prev_log_index = kv.second.next_index - 1;
        if (log_entry_get_term(msg->prev_log_index, &msg->prev_log_term)) {
            return -1;
        }
        if (serbuf && last_log_index >= kv.second.next_index) {
            auto bufcopy = std::unique_ptr<char[]>(new char[log_command_size]);
            memcpy(bufcopy.get(), serbuf, log_command_size);
            msg->entries.push_back(std::make_pair(term, std::move(bufcopy)));
        }
        out->output_messages.push_back(make_pair(kv.first, std::move(msg)));
    }

    return 0;
}

int
RaftSM::append_log_entry(const Term term, const char *serbuf)
{
    LogIndex new_index      = last_log_index + 1;
    unsigned long entry_pos = kLogEntriesOfs + (new_index - 1) * log_entry_size;
    int ret                 = 0;

    /* First write the current term. */
    if ((ret = log_u32_write(entry_pos, term))) {
        return ret;
    }

    /* Second, serialize the log entry and write the serialized content. */
    if ((ret = log_buf_write(entry_pos + sizeof(Term), serbuf,
                             log_command_size))) {
        return ret;
    }

    /* Update our last log index and term. */
    last_log_index = new_index;
    last_log_term  = term;

    IOS_INF() << "Append log entry term=" << last_log_term
              << ", index=" << last_log_index << endl;

    return ret;
}

int
RaftSM::apply_committed_entries()
{
    std::unique_ptr<char[]> serbuf;

    for (; last_applied < commit_index; last_applied++) {
        LogIndex next = last_applied + 1;
        int ret;

        if (!serbuf) {
            serbuf = std::unique_ptr<char[]>(new char[log_command_size]);
        }
        if ((ret = log_buf_read(
                 kLogEntriesOfs + (next - 1) * log_entry_size + sizeof(Term),
                 serbuf.get(), log_command_size))) {
            return ret;
        }
        apply(serbuf.get());
        IOS_INF() << "Entry " << next << " applied" << endl;
    }

    return 0;
}

int
RaftSM::request_vote_input(const RaftRequestVote &msg, RaftSMOutput *out)
{
    std::unique_ptr<RaftRequestVoteResp> resp;
    int ret;

    if (check_output_arg(out)) {
        return -1;
    }

    IOS_INF() << "Received VoteRequest(term=" << msg.term
              << ", cand=" << msg.candidate_id
              << ", last_log_term=" << msg.last_log_term
              << ", last_log_index=" << msg.last_log_index << ")" << endl;

    if ((ret = catch_up_term(msg.term, out)) < 0) {
        return ret;
    }

    resp       = make_unique<RaftRequestVoteResp>();
    resp->term = current_term;

    if (msg.term < current_term) {
        /* Received message belonging to an outdated term. Reply with a
         * nack and the updated term. */

        resp->vote_granted = false;
    } else {
        /* We grant our vote if we haven't voted for anyone in this term (or
         * we already voted for the candidate) and the candidate's log is at
         * least as up-to-date as ours. */
        resp->vote_granted =
            (voted_for.empty() || voted_for == msg.candidate_id) &&
            (msg.last_log_term > last_log_term ||
             (msg.last_log_term == last_log_term &&
              msg.last_log_index >= last_log_index));
    }

    if (resp->vote_granted && voted_for.empty()) {
        /* Register the vote on peristent memory. */
        if ((ret = vote_for_candidate(msg.candidate_id))) {
            return ret;
        }
    }
    IOS_INF() << "Vote for " << msg.candidate_id
              << (resp->vote_granted ? "" : " not") << " granted" << endl;

    out->output_messages.push_back(
        make_pair(msg.candidate_id, std::move(resp)));

    return 0;
}

int
RaftSM::request_vote_resp_input(const RaftRequestVoteResp &resp,
                                RaftSMOutput *out)
{
    int ret;

    if (check_output_arg(out)) {
        return -1;
    }

    IOS_INF() << "Received VoteRequestResp(term=" << resp.term
              << ", vote_granted=" << resp.vote_granted << ")" << endl;

    if ((ret = catch_up_term(resp.term, out))) {
        if (ret < 0) {
            return ret; /* error */
        }

        /* We are not candidates anymore, so there's nothing left to do. */
        return 0;
    }

    if (state == RaftState::Leader) {
        return 0; /* already leader, nothing to do */
    }

    if (!resp.vote_granted) {
        return 0; /* no vote, nothing to do */
    }

    if (++votes_collected < quorum()) {
        return 0; /* quorum not reached yet */
    }

    IOS_INF() << "Collected " << votes_collected << " votes, becoming leader"
              << endl;
    switch_state(RaftState::Leader);
    leader_id = local_id;

    /* Prepare heartbeat messages for the other replicas and set the
     * heartbeat timer. */
    if ((ret = prepare_append_entries(0, /*entry=*/nullptr, out))) {
        return ret;
    }
    out->timer_commands.push_back(RaftTimerCmd(this, RaftTimerType::HeartBeat,
                                               RaftTimerAction::Restart, 100));
    /* Also stop the election timer. */
    out->timer_commands.push_back(
        RaftTimerCmd(this, RaftTimerType::Election, RaftTimerAction::Stop));

    return 0;
}

int
RaftSM::append_entries_input(const RaftAppendEntries &msg, RaftSMOutput *out)
{
    std::unique_ptr<RaftAppendEntriesResp> resp;
    Term prev_log_term = 0;
    int ret;

    if (check_output_arg(out)) {
        return -1;
    }

    IOS_INF() << "AppendEntries(term=" << msg.term
              << ", leader_id=" << msg.leader_id
              << ", prev_log_index=" << msg.prev_log_index
              << ", prev_log_term=" << msg.prev_log_term
              << ", leader_commit=" << msg.leader_commit
              << ", num_entries=" << msg.entries.size() << ")" << endl;

    if ((ret = catch_up_term(msg.term, out)) < 0) {
        return ret;
    }

    if ((ret = back_to_follower(out))) {
        return ret;
    }

    resp                 = make_unique<RaftAppendEntriesResp>();
    resp->term           = current_term;
    resp->follower_id    = local_id;
    resp->last_log_index = last_log_index;

    if (msg.term < current_term) {
        /* Sender is outdated. Just reply false. */
        resp->success = false;
        out->output_messages.push_back(
            make_pair(msg.leader_id, std::move(resp)));
        return 0;
    }

    leader_id = msg.leader_id;

    if (msg.entries.empty()) {
        /* Heartbeat message, we don't need to reply. */
        return 0;
    }

    /* Check if we can accept the entries. */
    if ((ret = log_entry_get_term(msg.prev_log_index, &prev_log_term)) < 0) {
        return ret;
    }
    resp->success = msg.prev_log_index <= last_log_index && ret == 0 &&
                    msg.prev_log_term == prev_log_term;
    if (resp->success) {
        last_log_index = msg.prev_log_index;
        // TODO truncate log at last_log_index
        for (const auto &entry : msg.entries) {
            Term term                = entry.first;
            const char *const serbuf = entry.second.get();

            if ((ret = append_log_entry(term, serbuf))) {
                return ret;
            }
        }
        resp->last_log_index = last_log_index;
    }

    if (msg.leader_commit > commit_index) {
        commit_index = std::min(msg.leader_commit, last_log_index);
        if ((ret = apply_committed_entries())) {
            return ret;
        }
    }

    out->output_messages.push_back(make_pair(leader_id, std::move(resp)));

    return 0;
}

int
RaftSM::append_entries_resp_input(const RaftAppendEntriesResp &resp,
                                  RaftSMOutput *out)
{
    int ret;

    if (check_output_arg(out)) {
        return -1;
    }

    IOS_INF() << "Received AppendEntriesResp(term=" << resp.term
              << ", follower_id=" << resp.follower_id
              << ", last_log_index=" << resp.last_log_index
              << ", success=" << resp.success << ")" << endl;

    if ((ret = catch_up_term(resp.term, out))) {
        if (ret < 0) {
            return ret;
        }

        /* We are not the leader anymore. */
        return 0;
    }

    if (!servers.count(resp.follower_id)) {
        IOS_ERR() << "Replica " << resp.follower_id << " does not exist"
                  << endl;
        return -1;
    }

    if (resp.success) {
        LogIndex next_commit_index = commit_index;

        /* On success we update the next_index. */
        assert(resp.last_log_index + 1 > servers[resp.follower_id].next_index);
        servers[resp.follower_id].next_index  = resp.last_log_index + 1;
        servers[resp.follower_id].match_index = resp.last_log_index;
        /* Try to update the commit_index. We need to find the highest N
         * such that N > commit_index and that match_index >= N for a majority
         * of the replicas (we as a leader count as a replica that has
         * match_index == last_log_index). */
        while (next_commit_index <= last_log_index) {
            auto match_indices_quorum = [this](LogIndex index) -> bool {
                /* When computing the quorum we need to exclude ourselves
                 * (hence the we subtract one). */
                int needed = static_cast<int>(quorum()) - 1;
                for (const auto &kv : servers) {
                    if (kv.second.match_index >= index && --needed <= 0) {
                        return true;
                    }
                }
                return false;
            };
            if (match_indices_quorum(next_commit_index + 1)) {
                next_commit_index++;
            } else {
                break;
            }
        }
        if (next_commit_index != commit_index) {
            /* We cannot update commit_index only if log[N].term ==
             * current_term, that is if the entry N was replicated by us. */
            Term term;
            if ((ret = log_entry_get_term(next_commit_index, &term))) {
                return ret;
            }
            if (term == current_term) {
                IOS_INF() << "Leader commit index " << commit_index << " --> "
                          << next_commit_index << endl;
                commit_index = next_commit_index;
                if ((ret = apply_committed_entries())) {
                    return ret;
                }
            }
        }
    } else {
        /* Failure comes from log inconsistencies. We need to decrement
         * next index and retry. */
        assert(servers[resp.follower_id].next_index > 0);
        servers[resp.follower_id].next_index--;
    }

    return 0;
}

int
RaftSM::timer_expired(RaftTimerType type, RaftSMOutput *out)
{
    int ret;

    if (check_output_arg(out)) {
        return -1;
    }

    if (type == RaftTimerType::Election) {
        /* The election timer fired. */
        IOS_INF() << "Election timer expired" << endl;
        if (state == RaftState::Leader) {
            /* Nothing to do. */
            return 0;
        }
        /* Switch to candidate and increment current term. */
        switch_state(RaftState::Candidate);
        if ((ret = log_u32_write(kLogCurrentTermOfs, ++current_term))) {
            return ret;
        }
        /* Vote for myself. */
        if ((ret = vote_for_candidate(local_id))) {
            return ret;
        }
        votes_collected = 1;
        /* Reset the election timer in case we lose the election. */
        out->timer_commands.push_back(RaftTimerCmd(
            this, RaftTimerType::Election, RaftTimerAction::Restart,
            rand_int_in_range(200, 500)));
        /* Prepare RequestVote messages for the other servers. */
        for (const auto &kv : servers) {
            auto msg            = make_unique<RaftRequestVote>();
            msg->term           = current_term;
            msg->candidate_id   = local_id;
            msg->last_log_index = last_log_index;
            msg->last_log_term  = last_log_term;
            out->output_messages.push_back(make_pair(kv.first, std::move(msg)));
        }

    } else if (type == RaftTimerType::HeartBeat) {
        /* The heartbeat timer fired. */
        IOS_INF() << "Hearbeat timer expired" << endl;
        /* Send new heartbeat messages and rearm the timer. */
        if ((ret = prepare_append_entries(0, /*entry=*/nullptr, out))) {
            return ret;
        }
        out->timer_commands.push_back(RaftTimerCmd(
            this, RaftTimerType::HeartBeat, RaftTimerAction::Restart, 100));
    }

    return 0;
}

int
RaftSM::submit(const char *const serbuf, LogIndex *request_id,
               RaftSMOutput *out)
{
    int ret;

    /* Serialize the new entry and append it to the local log. */
    if ((ret = append_log_entry(current_term, serbuf))) {
        return ret;
    }

    /* Prepare RaftAppendEntries messages to be sent to the other
     * servers. */
    if ((ret = prepare_append_entries(current_term, serbuf, out))) {
        return ret;
    }

    *request_id = last_log_index;

    return 0;
}
