/*
 * RAFT protocol for fault-tolerant DIF internal components.
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

#ifndef __RAFT_H__
#define __RAFT_H__

#include <cstdint>
#include <string>
#include <list>

using Term     = uint32_t;
using LogIndex = uint32_t;

enum class RaftState {
    Follower = 0,
    Candidate,
    Leader,
};

/* Raft state machine. */
class RaftSM {
    RaftState state;

public:
    RaftSM();
};

/* Base class for log entries. Users must extend this class
 * by inheritance to associated a specific command for the
 * replicated state machine. */
struct RaftLogEntry {
    /* The term in which the entry was created. */
    Term term;

    /* How this entry must be serialized. */
    virtual char *serialize() const = 0;
};

/* Base class for all the Raft messages. */
struct RaftMessage {
    Term term;
};

struct RaftRequestVote : public RaftMessage {
    /* RaftMessage::term is candidate's term. */

    /* Candidate requesting vote. */
    std::string candidate_id;

    /* Index of candidate's last log entry. */
    LogIndex last_log_index;

    /* Term of candidate's last log entry. */
    Term last_log_term;
};

struct RaftRequestVoteResp : public RaftMessage {
    /* RaftMessage::term is the current term as known by
     * the peer, for the candidate to update itself. */

    /* Vote response: true means candidate received vote. */
    bool vote_granted;
};

struct RaftAppendEntries : public RaftMessage {
    /* RaftMessage::term is the current term as known by the leader. */

    /* Id of the leader, so that followers can redirect clients. */
    std::string leader_id;

    /* Index of the log entry immediately preceding new ones. */
    LogIndex prev_log_index;

    /* Term of pref_log_index entry. */
    Term perf_log_term;

    /* Leader's commit index. */
    LogIndex leader_commit;

    /* Log entries to store (empty for heartbeat). There may be
     * more than one for efficiency. */
    std::list<RaftLogEntry *> entries;
};

struct RaftAppendEntriesResp : public RaftMessage {
    /* RaftMessage::term is the current term as known by
     * the peer, for the leader to update itself. */

    /* True if the follower's last entry matched prev_log_index
     * and prev_log_term as specified in the request. If false
     * the leader should retry with an older log entry. */
    bool success;
};

#endif /* __RAFT_H__ */
