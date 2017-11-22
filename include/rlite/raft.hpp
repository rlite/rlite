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
#include <map>
#include <fstream>

using Term      = uint32_t;
using LogIndex  = uint32_t;
using ReplicaId = std::string;

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
    ReplicaId candidate_id;

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
    ReplicaId leader_id;

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

enum class RaftTimerType {
    Invalid = 0,
    Election,
    HeartBeat,
    LogReplication,
};

enum class RaftTimerAction {
    Invalid = 0,
    Set,
    Stop,
};

struct RaftTimerCmd {
    RaftTimerType type     = RaftTimerType::Invalid;
    RaftTimerAction action = RaftTimerAction::Invalid;
    uint32_t milliseconds  = 0;
};

/* The output of an invocation of the Raft state machine. May contain
 * some messages to send to the other replicas and command to start
 * or stop some timers. */
struct RaftSMOutput {
    std::list<std::pair<ReplicaId, RaftMessage *> > output_messages;
    std::list<RaftTimerCmd> timer_commands;
};

enum class RaftState {
    Follower = 0,
    Candidate,
    Leader,
};

/* Raft state machine. */
class RaftSM {
    /* =================================================================
     * Persistent state on all servers. Updated to stable storage before
     * responding to RPCs. Here we keep shadow copies.
     */

    /* Latest term this replica has seen. Initialized to 0 on first
     * boot (when there is no persistent file), then it increases
     * monotonically. */
    Term current_term = 0;

    /* Identifier of the candidate that received vote in current
     * term (or NULL if none). */
    ReplicaId voted_for;

    /* Log entries (only on disc). Each entry containes a command for the
     * replicated state machine and the term when entry was received by the
     * leader. The first index in the log is 1 (and not 0). */

    /* =================================================================
     * Volatile state for leaders.
     */

    /* For each replica, index of the next log entry to send to
     * that server. Initialized to leader's last log index + 1. */
    std::map<ReplicaId, LogIndex> next_index;

    /* For each replica, index of highest log entry known to
     * be replicated on that replica. Initialized to 0, increases
     * monotonically. */
    std::map<ReplicaId, LogIndex> match_index;

    /* =================================================================
     * Volatile state common to all the replicas.
     */

    /* Current state for the Raft state machine. */
    RaftState state = RaftState::Follower;

    /* Index of the highest log entry known to be committed.
     * Initialized to 0, increases monotonically. */
    LogIndex commit_index = 0;

    /* Index of the highest entry fed to the local replica of the state
     * machine. Initialized to 0, increases monotonically. */
    LogIndex last_applied = 0;

    /* File descriptor for the log file. */
    std::fstream logfile;

public:
    RaftSM() = default;
    ~RaftSM();
    int Init(const std::string &logfilename);

    /* Called by the user when the corresponding message is
     * received. Returns results in the 'out' argument. */
    int RequestVoteInput(const RaftRequestVote &msg, RaftSMOutput *out);
    int RequestVoteRespInput(const RaftRequestVote &msg, RaftSMOutput *out);
    int AppendEntriesInput(const RaftAppendEntries &msg, RaftSMOutput *out);
    int AppendEntriesRespInput(const RaftAppendEntries &msg, RaftSMOutput *out);

    /* Called by the user when a timer requested by Raft expired. */
    int TimerExpired(RaftTimerType, RaftSMOutput *out);
};

#endif /* __RAFT_H__ */
