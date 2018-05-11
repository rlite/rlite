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
#include <iostream>
#include <memory>
#include <chrono>

namespace raft {

using Term      = uint32_t;
using LogIndex  = uint32_t;
using ReplicaId = std::string;

/* Base class for all the Raft messages. */
struct RaftMessage {
    Term term;
    virtual ~RaftMessage() {} /* make it polymorphic */
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

    /* Leader's commit index. */
    LogIndex leader_commit;

    /* Index of the log entry immediately preceding new ones. */
    LogIndex prev_log_index;

    /* Term of prev_log_index entry. */
    Term prev_log_term;

    /* Log entries to store (empty for heartbeat). There may be
     * more than one for efficiency. */
    std::list<std::pair<Term, std::unique_ptr<char[]>>> entries;
};

struct RaftAppendEntriesResp : public RaftMessage {
    /* RaftMessage::term is the current term as known by
     * the peer, for the leader to update itself. */

    /* Id of the responding follower. */
    ReplicaId follower_id;

    /* On success, the new last log index of the follower.
     * On failure, it matches the prev_log_index field of
     * the corresponding AppendEntries request.
     * In both cases this field is used by the leader to
     * update next_index_acked and next_index_unacked. */
    LogIndex log_index;

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
    Restart,
    Stop,
};

class RaftSM;

struct RaftTimerCmd {
    RaftSM *sm                             = nullptr;
    RaftTimerType type                     = RaftTimerType::Invalid;
    RaftTimerAction action                 = RaftTimerAction::Invalid;
    std::chrono::milliseconds milliseconds = std::chrono::milliseconds(0);

    RaftTimerCmd(RaftSM *_sm, RaftTimerType ty, RaftTimerAction act,
                 std::chrono::milliseconds ms = std::chrono::milliseconds(0))
        : sm(_sm), type(ty), action(act), milliseconds(ms)
    {
    }
};

/* The output of an invocation of the Raft state machine. May contain
 * some messages to send to the other replicas, commands to start
 * or stop some timers, and log entries that have been commited to
 * the replicated state machine. */
struct RaftSMOutput {
    RaftSMOutput()                     = default;
    RaftSMOutput(const RaftSMOutput &) = delete;
    RaftSMOutput &operator=(const RaftSMOutput &) = delete;
    RaftSMOutput(RaftSMOutput &&)                 = default;
    RaftSMOutput &operator=(RaftSMOutput &&) = default;

    std::list<std::pair<ReplicaId, std::unique_ptr<RaftMessage>>>
        output_messages;
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

    /* Log entries (only on disc). Each entry contains a command for the
     * replicated state machine and the term when entry was received by the
     * leader. The first index in the log is 1 (and not 0). */

    /* =================================================================
     * Volatile state for leaders.
     */

    struct Server {
        /* For each replica, next_index is the index of the next log entry to
         * send to that server. Initialized to leader's last log index + 1. We
         * make a slight variation to allow to pipeline RaftAppendEntries
         * messages towards the same replica:
         *   - on client submit or retransmission we send the log entry
         *     indexed by next_index_unacked and we increment it right away
         *   - on positive/negative response we update next_index_acked as
         * described by the algorithm (for next_index)
         *   - on negative response we also reset next_index_unacked to
         *     next_index_acked (after the latter has been decremented)
         * In this way we split next_index into two separate variables: the
         * meaning of next_index_acked is "the first log entry still to be
         * acked"; the meaning of next_index_unacked is "the next log entry to
         * be sent". In the paper next_index has both meanings, preventing
         * pipelining.
         */
        LogIndex next_index_acked;
        LogIndex next_index_unacked;

        /* For each replica, index of highest log entry known to
         * be replicated on that replica. Initialized to 0, increases
         * monotonically. */
        LogIndex match_index;

        /* We record the last time we sent a RaftAppendEntries message with
         * one or more entries. This is used to avoid useless retransmissions
         * that closely follow a submit(). */
        std::chrono::system_clock::time_point last_ae_time;
    };

    std::map<ReplicaId, Server> servers;

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

    /* A name for this SM, just for logging purposes. */
    const std::string name;

    /* My identifier. */
    const ReplicaId local_id;

    /* Id of the leader, useful to redirect clients. */
    ReplicaId leader_id;

    /* Index of the last entry written in the local log. */
    LogIndex last_log_index = 0;

    /* Term of the last log entry. */
    Term last_log_term = 0;

    /* How many votes we collected as a candidate. */
    unsigned int votes_collected = 0;

    /* Name of the log file. */
    const std::string logfilename;

    /* File descriptor for the log file. */
    std::fstream logfile;

    /* Size of a log entry (with and without term info). */
    const size_t log_entry_size   = sizeof(Term);
    const size_t log_command_size = 0;

    /* For logging of Raft internal operations. */
    std::ostream &ios_err;
    std::ostream &ios_inf;

    static constexpr uint32_t kLogMagicNumber         = 0x89ae01caU;
    static constexpr unsigned long kLogMagicOfs       = 0;
    static constexpr unsigned long kLogCurrentTermOfs = 4;
    static constexpr unsigned long kLogVotedForOfs    = 8;
    static constexpr unsigned long kLogEntriesOfs     = 128;
    static constexpr size_t kLogVotedForSize = kLogEntriesOfs - kLogVotedForOfs;

    /* Argument for RaftSM::prepare_append_entries() that specifies
     * its behaviour (send all the unacked log entries or only the
     * ones that have not been sent yet). */
    enum class LogReplicateStrategy {
        Unacked = 0,
        Unsent,
    };

    /* Getter/setters for replica persistent state. */
    int log_u32_write(unsigned long pos, uint32_t val);
    int log_u32_read(unsigned long pos, uint32_t *val);
    int log_buf_write(unsigned long pos, const char *buf, size_t len);
    int log_buf_read(unsigned long pos, char *buf, size_t len);
    int magic_check();
    int log_open(bool first_boot);
    int log_disk_flush();
    int log_truncate(LogIndex index);

    /* Logging helpers. */
    std::string curtime_string(void)
    {
        time_t ctime = time(nullptr);
        struct tm *time_info;
        char tbuf[9];

        time_info = localtime(&ctime);
        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", time_info);

        return std::string(tbuf);
    }

    std::ostream &IOS_ERR()
    {
        return ios_err << "[" << curtime_string() << "](" << name << ") ";
    }
    std::ostream &IOS_INF()
    {
        return ios_inf << "[" << curtime_string() << "](" << name << ") ";
    }

    int check_output_arg(RaftSMOutput *out);
    std::chrono::milliseconds rand_time_in_range(
        std::chrono::milliseconds left, std::chrono::milliseconds right);
    void switch_state(RaftState next);
    std::string state_repr(RaftState st) const;
    int vote_for_candidate(ReplicaId candidate);
    int catch_up_term(Term term, RaftSMOutput *out);
    int back_to_follower(RaftSMOutput *out);
    unsigned int quorum() const;
    int prepare_append_entries(LogReplicateStrategy strategy,
                               RaftSMOutput *out);
    int log_entry_get_term(LogIndex index, Term *term);
    int log_entry_get_command(LogIndex index, char *const serbuf);
    int append_log_entry(const Term term, const char *serbuf);
    int apply_committed_entries();

    std::chrono::milliseconds ElectionTimeoutMin =
        std::chrono::milliseconds(200);
    std::chrono::milliseconds ElectionTimeoutMax =
        std::chrono::milliseconds(500);
    std::chrono::milliseconds HeartbeatTimeout = std::chrono::milliseconds(100);

    unsigned int verbosity = kVerboseVery;

    /* Statistics. */
    struct Stats {
        /* Number of discarded log entries, due to partial replication. */
        unsigned int discarded = 0;
    } stats;

public:
    RaftSM(const std::string &smname, const ReplicaId &myname,
           std::string logname, size_t cmd_size, std::ostream &ioe,
           std::ostream &ioi)
        : name(smname),
          local_id(myname),
          logfilename(logname),
          log_entry_size(sizeof(Term) + cmd_size),
          log_command_size(cmd_size),
          ios_err(ioe),
          ios_inf(ioi)
    {
    }
    int init(const std::list<ReplicaId> peers, RaftSMOutput *out);

    /* The user doesn't need this Raft SM anymore. Delete the log on disk. */
    void shutdown();

    /* Called by the user when the corresponding message is
     * received. Returns results in the 'out' argument. */
    int request_vote_input(const RaftRequestVote &msg, RaftSMOutput *out);
    int request_vote_resp_input(const RaftRequestVoteResp &msg,
                                RaftSMOutput *out);
    int append_entries_input(const RaftAppendEntries &msg, RaftSMOutput *out);
    int append_entries_resp_input(const RaftAppendEntriesResp &msg,
                                  RaftSMOutput *out);

    /* Called by the user when a timer requested by Raft expired. */
    int timer_expired(RaftTimerType, RaftSMOutput *out);

    /* Called by the user when it wants to submit a new log entry to
     * the replicated state machine. If 'log_index_p' is not nullptr,
     * it is filled with the index of the log entry allocated for
     * this request. */
    int submit(const char *const serbuf, LogIndex *log_index_p,
               RaftSMOutput *out);

    /* Called by the Raft state machine when a log entry needs to
     * be applied to the replicated state machine. */
    virtual int apply(LogIndex index, const char *const serbuf) = 0;
    virtual ~RaftSM();

    /* True if this Raft SM is the current leader. */
    bool leader() const { return state == RaftState::Leader; }

    /* Name of the current leader (if we know it). */
    ReplicaId leader_name() const { return leader_id; }

    bool leader_elected() const { return !leader_id.empty(); }

    std::string local_name() const { return local_id; }
    std::string sm_name() const { return name; }

    int set_election_timeout(std::chrono::milliseconds tmin,
                             std::chrono::milliseconds tmax)
    {
        if (tmin > tmax) {
            return -1;
        }

        ElectionTimeoutMin = tmin;
        ElectionTimeoutMax = tmax;

        return 0;
    }

    std::chrono::milliseconds get_election_timeout_max() const
    {
        return ElectionTimeoutMax;
    }

    int set_heartbeat_timeout(std::chrono::milliseconds t)
    {
        HeartbeatTimeout = t;
        return 0;
    }

    std::chrono::milliseconds get_heartbeat_timeout() const
    {
        return HeartbeatTimeout;
    }

    Stats get_stats() { return stats; };

    static constexpr unsigned int kVerboseQuiet = 0;
    static constexpr unsigned int kVerboseInfo  = 6;
    static constexpr unsigned int kVerboseVery  = 10;

    void set_verbosity(unsigned int level)
    {
        verbosity = level; /* no need to check */
    }

    /* At most 1000 bytes of log chunk per each RaftAppendEntries
     * message. */
    static constexpr size_t kMaxLogChunkBytes = 1000;

    static constexpr unsigned int kRetransmissionMsecs = 0;
};

} /* namespace raft */

#endif /* __RAFT_H__ */
