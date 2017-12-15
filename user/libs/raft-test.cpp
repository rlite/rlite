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

enum class FailingReplica {
    Invalid = 0,
    Follower,
    Leader,
};

struct TestEvent {
    TestEventType event_type;
    unsigned int abstime           = 0;
    TestReplica *sm                = nullptr;
    RaftTimerType ttype            = RaftTimerType::Invalid;
    FailingReplica failing_replica = FailingReplica::Invalid;
    unsigned int failing_id        = 0;

    bool operator<(const TestEvent &o) const { return abstime < o.abstime; }
    bool operator>=(const TestEvent &o) const { return !(*this < o); }

    bool is_interesting() const
    {
        return event_type != TestEventType::RaftTimer;
    }

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

    static TestEvent CreateFailureEvent(unsigned int t, FailingReplica fr,
                                        unsigned int fid)
    {
        TestEvent e;
        e.event_type      = TestEventType::SMFailure;
        e.abstime         = t;
        e.failing_replica = fr;
        e.failing_id      = fid;
        return e;
    }

    static TestEvent CreateRespawnEvent(unsigned int t, unsigned int fid)
    {
        TestEvent e;
        e.event_type = TestEventType::SMRespawn;
        e.abstime    = t;
        e.failing_id = fid;
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
    map<unsigned int, TestReplica *> failed_replicas;
    RaftSMOutput output;

    /* Sort input events in case they are not. */
    events.sort();

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

    /* Helpers to get the leader or any follower that is up. */
    auto get_leader = [&replicas]() -> TestReplica * {
        for (const auto &kv : replicas) {
            if (kv.second->leader() && kv.second->up()) {
                return kv.second.get();
            }
        }
        return nullptr;
    };
    auto get_follower = [&replicas]() -> TestReplica * {
        for (const auto &kv : replicas) {
            if (kv.second->up() && !kv.second->leader()) {
                return kv.second.get();
            }
        }
        return nullptr;
    };

    while (!should_stop(t_last_ievent + grace_period)) {
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
                /* Don't count heartbeat messages as interesting events. */
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
        if (!output.timer_commands.empty()) {
            events.sort();
        }

        /* Process all the timers expired so far, updating the associated
         * Raft state machine. */
        while (!events.empty()) {
            const TestEvent &next = events.front();
            bool consume_event    = true;

            if (t < next.abstime) {
                if (output_next.output_messages.empty() &&
                    output_next.timer_commands.empty()) {
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
                TestReplica *leader = get_leader();
                if (leader) {
                    uint32_t cmd = input_counter++;
                    LogIndex request_id;

                    if (leader->submit(reinterpret_cast<char *>(&cmd),
                                       &request_id, &output_next)) {
                        return -1;
                    }
                    cout << "Command " << cmd << " submitted" << endl;
                } else {
                    /* This can happen because no leader is currently elected
                     * or because the current leader is down. */
                    consume_event = false;
                    cout << "Client request postponed (no leader)" << endl;
                }
                break;
            }

            case TestEventType::SMFailure: {
                TestReplica *r = next.failing_replica == FailingReplica::Leader
                                     ? get_leader()
                                     : get_follower();
                if (r != nullptr) {
                    r->fail();
                    failed_replicas[next.failing_id] = r;
                    cout << "Replica " << r->local_name() << " failed" << endl;
                } else {
                    /* This may happen if no leader or no followers. */
                    consume_event = false;
                    cout << "Replica failure postponed" << endl;
                }
                break;
            }

            case TestEventType::SMRespawn: {
                TestReplica *r = failed_replicas[next.failing_id];
                int ret;
                assert(r != nullptr);
                failed_replicas.erase(next.failing_id);
                if ((ret = r->respawn(&output_next))) {
                    return ret;
                }
                cout << "Replica " << r->local_name() << " respawn" << endl;
                break;
            }
            }

            if (consume_event) {
                if (next.is_interesting()) {
                    t_last_ievent = t;
                }
                events.pop_front();
            } else {
                /* This event cannot happen now (i.e. no leader). Let's just
                 * postpone any significant event. */
                for (auto &e : events) {
                    if (e.is_interesting()) {
                        e.abstime += 200;
                    }
                }
                events.sort();
            }
        }

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
main(int argc, char **argv)
{
    /* Some function aliases useful to specify test vectors in a compact way. */
    const auto &Req                    = TestEvent::CreateRequestEvent;
    const auto &Fail                   = TestEvent::CreateFailureEvent;
    const auto &Respawn                = TestEvent::CreateRespawnEvent;
    const auto F                       = FailingReplica::Follower;
    const auto L                       = FailingReplica::Leader;
    list<list<TestEvent>> test_vectors = {
        /* No failures */
        {Req(240), Req(411), Req(600), Req(600), Req(601), Req(602), Req(658),
         Req(661), Req(721)},
        /* Two follower failures, no respawn. */
        {Req(350), Req(360), Fail(365, F, 0), Req(450), Req(370),
         Fail(450, F, 1), Req(454), Req(455), Req(550), Req(560)},
        /* One follower failure with immediate respawn. */
        {Req(301), Req(302), Fail(303, F, 0), Respawn(305, 0), Req(307),
         Req(309), Req(313)},
        /* One follower failure with respawn after some time. */
        {Req(301), Req(302), Fail(303, F, 0), Req(307), Req(309), Req(313),
         Respawn(500, 0), Req(600)},
        /* Leader failure with no respawn. */
        {Req(350), Req(355), Fail(359, L, 0), Req(450), Req(370), Req(454),
         Req(455), Req(550), Req(560)},
        /* Leader failure with respawn. */
        {Req(350), Req(355), Fail(359, L, 0), Req(450), Req(370), Req(454),
         Req(455), Req(550), Respawn(570, 0), Req(601), Req(608)},
    };
    int test_counter  = 1;
    int test_selector = -1;

    if (argc > 1) {
        test_selector = std::stoi(argv[1]);
        if (test_selector < 1 ||
            test_selector > static_cast<int>(test_vectors.size())) {
            cerr << "Invalid test selector " << test_selector << endl;
            return -1;
        }
    }

    srand(time(0));

    for (const auto &vector : test_vectors) {
        int ret;

        if (test_selector <= 0 || test_selector == test_counter) {
            ret = run_simulation(vector);
            cout << "Test #: " << test_counter;
            switch (ret) {
            case -1:
                cout << ": error occurred" << endl;
                return -1;
                break;
            case 1:
                cout << ": test failed" << endl;
                return -1;
                break;
            case 0:
                cout << ": test ok" << endl;
                break;
            }
        }
        ++test_counter;
    }

    return 0;
}
