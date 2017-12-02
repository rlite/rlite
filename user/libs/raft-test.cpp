/*
 * Unit tests for the Raft library.
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

#include <iostream>
#include <list>
#include <string>
#include <cstdint>
#include <cassert>
#include <cstring>
#include <functional>
#include <queue>
#include <random>
#include <ctime>
#include <memory>

#include "rlite/cpputils.hpp"
#include "rlite/raft.hpp"

using namespace std;

static string
logfile(const string &replica)
{
    return string("/tmp/raft_test_") + replica + "_log";
}

class TestReplica : public RaftSM {
    list<uint32_t> committed_commands;
    list<string> peers;
    bool failed = false;

public:
    TestReplica() = default;
    RL_NONCOPIABLE(TestReplica);
    TestReplica(const std::string &smname, const ReplicaId &myname,
                std::string logname, const list<string> &others)
        : RaftSM(smname, myname, logname,
                 /*cmd_size=*/sizeof(uint32_t), std::cerr, std::cout),
          peers(others)
    {
    }
    ~TestReplica() { shutdown(); }

    /* Apply a command to the replicated state machine. */
    virtual int apply(const char *const serbuf) override
    {
        uint32_t cmd = *(reinterpret_cast<const uint32_t *>(serbuf));
        committed_commands.push_back(cmd);
        return 0;
    }

    /* Called to emulate failure of a replica. The replica won't receive
     * messages until respawn. */
    void fail() { failed = true; }

    /* Is this replica alive? */
    bool up() const { return !failed; }

    /* Called to emulate a replica trying to recover after failure. */
    int respawn(RaftSMOutput *out)
    {
        failed = false;
        return init(peers, out);
    };

    bool check(uint32_t num_commands) const
    {
        uint32_t expected = 1;

        if (committed_commands.size() != num_commands) {
            return false;
        }
        for (auto cmd : committed_commands) {
            if (cmd != expected++) {
                return false;
            }
        }

        return true;
    }
};

enum class TestEventType {
    RaftTimer = 0,
    ClientRequest,
    SMFailure,
    SMRespawn,
};

struct TestEvent {
    TestEventType event_type;
    unsigned int abstime = 0;
    TestReplica *sm      = nullptr;
    RaftTimerType ttype  = RaftTimerType::Invalid;

    bool operator<(const TestEvent &o) const { return abstime < o.abstime; }
    bool operator>=(const TestEvent &o) const { return !(*this < o); }

    static TestEvent CreateTimerEvent(unsigned int t, TestReplica *_sm,
                                      RaftTimerType ty)
    {
        TestEvent e;
        e.event_type = TestEventType::RaftTimer;
        e.abstime    = t;
        e.sm         = _sm;
        e.ttype      = ty;
        return e;
    }

    static TestEvent CreateRequestEvent(unsigned int t)
    {
        TestEvent e;
        e.event_type = TestEventType::ClientRequest;
        e.abstime    = t;
        return e;
    }

    static TestEvent CreateFailureEvent(unsigned int t, TestReplica *_sm)
    {
        TestEvent e;
        e.event_type = TestEventType::SMFailure;
        e.abstime    = t;
        e.sm         = _sm;
        return e;
    }

    static TestEvent CreateRespawnEvent(unsigned int t, TestReplica *_sm)
    {
        TestEvent e;
        e.event_type = TestEventType::SMRespawn;
        e.abstime    = t;
        e.sm         = _sm;
        return e;
    }
};

int
main()
{
    list<string> names = {"r1", "r2", "r3", "r4", "r5"};
    map<string, std::unique_ptr<TestReplica>> replicas;
    list<TestEvent> events;
    unsigned int t           = 0; /* time */
    const unsigned int t_max = 800;
    uint32_t input_counter   = 1;
    RaftSMOutput output;

    srand(time(0));

    /* Clean up leftover logfiles, if any. */
    for (const auto &local : names) {
        remove(logfile(local).c_str());
    }

    /* Create and initialize all the replicas. */
    for (const auto &local : names) {
        string logfilename = logfile(local);
        list<string> peers;
        std::unique_ptr<TestReplica> sm;

        for (const auto &peer : names) {
            if (peer != local) {
                peers.push_back(peer);
            }
        }

        sm = make_unique<TestReplica>(
            /*smname=*/local + "-sm", /*myname=*/local, logfilename, peers);
        if (sm->respawn(&output)) {
            return -1;
        }
        replicas[local] = std::move(sm);
    }

    /* Push some client submission, failures and respawn events. */
    events.push_back(TestEvent::CreateRequestEvent(350));
    events.push_back(TestEvent::CreateRequestEvent(360));
    events.push_back(TestEvent::CreateFailureEvent(365, replicas["r3"].get()));
    events.push_back(TestEvent::CreateRequestEvent(370));
    events.push_back(TestEvent::CreateRequestEvent(450));
    events.push_back(TestEvent::CreateFailureEvent(450, replicas["r4"].get()));
    events.push_back(TestEvent::CreateRequestEvent(454));
    events.push_back(TestEvent::CreateRequestEvent(455));
    // events.push_back(TestEvent::CreateRespawnEvent(500,
    // replicas["r3"].get()));
    events.push_back(TestEvent::CreateRequestEvent(550));
    events.push_back(TestEvent::CreateRequestEvent(560));
    events.sort();

    /* Stop the simulation when we are over-time or when we run out
     * of messages and events (except for the heartbeat timeouts). */
    auto should_stop = [t, t_max, &output, &events]() -> bool {
        auto only_timeouts = [&events]() -> bool {
            for (const auto &e : events) {
                if (e.event_type != TestEventType::RaftTimer) {
                    return false;
                }
            }
            return true;
        };
        auto only_heartbeat_commands = [&output]() -> bool {
            for (const auto &c : output.timer_commands) {
                if (c.type != RaftTimerType::HeartBeat) {
                    return false;
                }
            }
            return true;
        };
        return t > t_max || (output.output_messages.empty() &&
                             only_heartbeat_commands() && only_timeouts());
    };

    while (!should_stop()) {
        list<TestEvent> postponed;
        unsigned int t_next = t + 1;
        RaftSMOutput output_next;

        cout << "| t = " << t << " |" << endl;

        /* Process current output messages. */
        for (const auto &p : output.output_messages) {
            auto *rv  = dynamic_cast<RaftRequestVote *>(p.second.get());
            auto *rvr = dynamic_cast<RaftRequestVoteResp *>(p.second.get());
            auto *ae  = dynamic_cast<RaftAppendEntries *>(p.second.get());
            auto *aer = dynamic_cast<RaftAppendEntriesResp *>(p.second.get());
            int r     = 0;

            assert(replicas.count(p.first));
            if (!replicas[p.first]->up()) {
                /* Replica is currently down, we just drop this message. */
            } else if (rv) {
                r = replicas[p.first]->request_vote_input(*rv, &output_next);
            } else if (rvr) {
                r = replicas[p.first]->request_vote_resp_input(*rvr,
                                                               &output_next);
            } else if (ae) {
                r = replicas[p.first]->append_entries_input(*ae, &output_next);
            } else if (aer) {
                r = replicas[p.first]->append_entries_resp_input(*aer,
                                                                 &output_next);
            } else {
                assert(false);
            }

            if (r) {
                return r;
            }
        }

        /* Process current timer commands. */
        for (const RaftTimerCmd &cmd : output.timer_commands) {
            for (auto it = events.begin(); it != events.end(); it++) {
                if (it->sm == cmd.sm && it->ttype == cmd.type) {
                    events.erase(it);
                    break;
                }
            }
            if (cmd.action == RaftTimerAction::Restart) {
                events.push_back(TestEvent::CreateTimerEvent(
                    t + cmd.milliseconds, dynamic_cast<TestReplica *>(cmd.sm),
                    cmd.type));
            } else {
                assert(cmd.action == RaftTimerAction::Stop);
            }
        }

        /* Process all the timers expired so far, updating the associated
         * Raft state machine. */
        events.sort();
        while (!events.empty()) {
            const TestEvent &next = events.front();
            if (t < next.abstime) {
                if (output_next.output_messages.empty() &&
                    output_next.timer_commands.empty() && postponed.empty()) {
                    /* No need to go step by step, we can jump to the next
                     * event. */
                    t_next = next.abstime;
                }
                break;
            }
            switch (next.event_type) {
            case TestEventType::RaftTimer: {
                /* This event is a timer firing. */
                if (next.sm->up() &&
                    next.sm->timer_expired(next.ttype, &output_next)) {
                    return -1;
                }
                break;
            }

            case TestEventType::ClientRequest: {
                /* This event is a client submission. */
                bool submitted = false;
                for (const auto &kv : replicas) {
                    if (kv.second->leader() && kv.second->up()) {
                        uint32_t cmd = input_counter++;
                        LogIndex request_id;

                        if (kv.second->submit(reinterpret_cast<char *>(&cmd),
                                              &request_id, &output_next)) {
                            return -1;
                        }
                        submitted = true;
                        cout << "Command " << cmd << " submitted" << endl;
                        break;
                    }
                }
                if (!submitted) {
                    /* This can happen because no leader is currently elected
                     * or because the current leader is down. */
                    postponed.push_back(TestEvent::CreateRequestEvent(t + 100));
                    cout << "Client request postponed (no leader)" << endl;
                }
                break;
            }

            case TestEventType::SMFailure: {
                next.sm->fail();
                cout << "Replica " << next.sm->local_name() << " failed"
                     << endl;
                break;
            }

            case TestEventType::SMRespawn: {
                next.sm->respawn(&output_next);
                cout << "Replica " << next.sm->local_name() << " respawn"
                     << endl;
                break;
            }
            }
            events.pop_front();
        }
        /* Append the 'postponed' list at the end of the events list. */
        events.splice(events.end(), postponed);

        /* Update time and Raft state machine output. */
        t      = t_next;
        output = std::move(output_next);
    }

    for (const auto &kv : replicas) {
        if (kv.second->up()) {
            cout << "Replica " << kv.first << " up, check " << std::boolalpha
                 << kv.second->check(input_counter - 1) << endl;
        }
    }

    return 0;
}
