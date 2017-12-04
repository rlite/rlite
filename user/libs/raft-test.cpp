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
    string smname;
    RaftTimerType ttype = RaftTimerType::Invalid;

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

    static TestEvent CreateFailureEvent(unsigned int t, const string &name)
    {
        TestEvent e;
        e.event_type = TestEventType::SMFailure;
        e.abstime    = t;
        e.smname     = name;
        return e;
    }

    static TestEvent CreateRespawnEvent(unsigned int t, const string &name)
    {
        TestEvent e;
        e.event_type = TestEventType::SMRespawn;
        e.abstime    = t;
        e.smname     = name;
        return e;
    }
};

/* Returns 0 on test success, 1 on test failure, -1 on error. */
int
run_simulation(const list<TestEvent> &external_events)
{
    list<string> names = {"r1", "r2", "r3", "r4", "r5"};
    map<string, std::unique_ptr<TestReplica>> replicas;
    list<TestEvent> events     = external_events;
    unsigned int t             = 0; /* time */
    unsigned int t_last_ievent = t; /* time of last interesting event */
    uint32_t input_counter     = 1;
    RaftSMOutput output;

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

    auto compute_grace_period = [&replicas]() -> unsigned int {
        for (const auto &kv : replicas) {
            return 2 * kv.second->get_heartbeat_timeout();
        }
        assert(false);
        return 0;
    };
    const unsigned int grace_period = compute_grace_period();

    events.sort();

    /* Stop the simulation when there are no more interesting events scheduled
     * (client submissions, replica failure, replica respawn or non-heartbeat
     * message), a leader is up and running and nothing interesting happened
     * for the last grace period (two heartbeat timeouts). */
    auto should_stop = [&t, &replicas, &events](unsigned int t_max) -> bool {
        auto only_timeouts = [&events]() -> bool {
            for (const auto &e : events) {
                if (e.event_type != TestEventType::RaftTimer) {
                    return false;
                }
            }
            return true;
        };
        auto leader_is_up = [&replicas]() -> bool {
            for (const auto &kv : replicas) {
                if (kv.second->leader() && kv.second->up()) {
                    return true;
                }
            }
            return false;
        };
        return leader_is_up() && only_timeouts() && t > t_max;
    };

    while (!should_stop(t_last_ievent + grace_period)) {
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

            if (!ae || !ae->entries.empty()) {
                t_last_ievent = t;
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
                        t_last_ievent = t;
                        submitted     = true;
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
                assert(replicas.count(next.smname));
                replicas[next.smname]->fail();
                t_last_ievent = t;
                cout << "Replica " << next.smname << " failed" << endl;
                break;
            }

            case TestEventType::SMRespawn: {
                assert(replicas.count(next.smname));
                replicas[next.smname]->respawn(&output_next);
                t_last_ievent = t;
                cout << "Replica " << next.smname << " respawn" << endl;
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
        if (kv.second->up() && !kv.second->check(input_counter - 1)) {
            cout << "Check failed for replica " << kv.first << endl;
            return 1;
        }
    }

    return 0;
}

int
main()
{
    srand(time(0));

    {
        list<TestEvent> events;
        int ret;

        /* Push some client submission, failures and respawn events. */
        events.push_back(TestEvent::CreateRequestEvent(350));
        events.push_back(TestEvent::CreateRequestEvent(360));
        events.push_back(TestEvent::CreateFailureEvent(365, "r3"));
        events.push_back(TestEvent::CreateRequestEvent(370));
        events.push_back(TestEvent::CreateRequestEvent(450));
        events.push_back(TestEvent::CreateFailureEvent(450, "r4"));
        events.push_back(TestEvent::CreateRequestEvent(454));
        events.push_back(TestEvent::CreateRequestEvent(455));
        // events.push_back(TestEvent::CreateRespawnEvent(500, "r3"));
        events.push_back(TestEvent::CreateRequestEvent(550));
        events.push_back(TestEvent::CreateRequestEvent(560));

        ret = run_simulation(events);
        switch (ret) {
        case -1:
            cout << "Error occurred during test run" << endl;
            return -1;
            break;
        case 1:
            cout << "Test failure" << endl;
            return -1;
            break;
        case 0:
            cout << "Test success" << endl;
            break;
        }
    }

    return 0;
}
