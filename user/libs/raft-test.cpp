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
#include <set>
#include <map>
#include <unordered_map>
#include <chrono>

#include "rlite/cpputils.hpp"
#include "rlite/raft.hpp"

using namespace std;
using namespace raft;

static string
logfile(const string &replica)
{
    return string("/tmp/raft_test_") + replica + "_log";
}

class TestReplica : public RaftSM {
    /* Commands committed to the replicated state machine. */
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

    /* Apply (commit) a command to the replicated state machine. */
    virtual int apply(LogIndex index, const char *const serbuf) override
    {
        uint32_t cmd = *(reinterpret_cast<const uint32_t *>(serbuf));
        committed_commands.push_back(cmd);
        return 0;
    }

    /* Called to emulate failure of a replica. The replica won't receive
     * messages until respawn. We clearly need to discard the replicated
     * state machine. */
    void fail()
    {
        failed = true;
        committed_commands.clear();
    }

    /* Is this replica alive? */
    bool up() const { return !failed; }

    /* Called to emulate a replica trying to recover after failure. */
    int respawn(RaftSMOutput *out)
    {
        failed = false;
        return init(peers, out);
    };

    /* Checks that committed commands are all there, and in the expected
     * order. Currently unused. */
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

    bool cross_check(const TestReplica &o) const
    {
        return committed_commands == o.committed_commands;
    }

    bool something_committed() const { return !committed_commands.empty(); }

    /* Go over the commands committed so far, and check if there
     * are any missing numbers (adding them to the output argument). */
    set<uint32_t> get_missing_commands(set<uint32_t> acc, uint32_t Max) const
    {
        set<uint32_t> got;

        for (auto cmd : committed_commands) {
            got.insert(cmd);
            Max = std::max(Max, cmd);
        }
        for (uint32_t cmd = 1; cmd <= Max; cmd++) {
            if (got.count(cmd) == 0) { /* we miss this one */
                acc.insert(cmd);
            }
        }

        return acc;
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
    chrono::milliseconds abstime   = chrono::milliseconds(0);
    TestReplica *sm                = nullptr;
    RaftTimerType ttype            = RaftTimerType::Invalid;
    FailingReplica failing_replica = FailingReplica::Invalid;
    unsigned int failing_id        = 0; /* for failure and recovery */
    uint32_t cmd                   = 0; /* for client requests */

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
        e.abstime    = chrono::milliseconds(t);
        e.sm         = _sm;
        e.ttype      = ty;
        return e;
    }

    static TestEvent CreateRequestEvent(unsigned int t)
    {
        TestEvent e;
        e.event_type = TestEventType::ClientRequest;
        e.abstime    = chrono::milliseconds(t);
        return e;
    }

    static TestEvent CreateFailureEvent(unsigned int t, FailingReplica fr,
                                        unsigned int fid)
    {
        TestEvent e;
        e.event_type      = TestEventType::SMFailure;
        e.abstime         = chrono::milliseconds(t);
        e.failing_replica = fr;
        e.failing_id      = fid;
        return e;
    }

    static TestEvent CreateRespawnEvent(unsigned int t, unsigned int fid)
    {
        TestEvent e;
        e.event_type = TestEventType::SMRespawn;
        e.abstime    = chrono::milliseconds(t);
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
    list<TestEvent> events             = external_events;
    chrono::milliseconds t             = chrono::milliseconds(0); /* time */
    chrono::milliseconds t_last_ievent = t; /* time of last interesting event */
    uint32_t input_counter             = 0;
    map<unsigned int, TestReplica *> failed_replicas;
    bool retransmit_check = true;
    RaftSMOutput output;

    /* Sort input events in case they are not. */
    events.sort();

    /* Assign a progressive command number to each client request. */
    for (auto &e : events) {
        if (e.event_type == TestEventType::ClientRequest) {
            e.cmd = ++input_counter;
        }
    }

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
        /* Zero the retransmission timeout, because this would make
         * the test fail, as time is emulated. */
        sm->set_retransmission_timeout(std::chrono::seconds::zero());
        replicas[local] = std::move(sm);
    }

    auto compute_grace_period = [&replicas]() -> chrono::milliseconds {
        for (const auto &kv : replicas) {
            return 2 * kv.second->get_heartbeat_timeout();
        }
        assert(false);
        return chrono::milliseconds(0);
    };
    const chrono::milliseconds grace_period = compute_grace_period();

    /* Stop the simulation when there are no more interesting events scheduled
     * (client submissions, replica failure, replica respawn or non-heartbeat
     * message), a leader is up and running and nothing interesting happened
     * for the last grace period (two heartbeat timeouts). */
    auto should_stop = [&t, &replicas,
                        &events](chrono::milliseconds t_max) -> bool {
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
        chrono::milliseconds t_next = t + chrono::milliseconds(1);
        RaftSMOutput output_next;

        cout << "| t = " << t.count() << " |" << endl;

        /* Process current output messages. */
        for (const auto &p : output.output_messages) {
            auto *rv  = dynamic_cast<RaftRequestVote *>(p.second.get());
            auto *rvr = dynamic_cast<RaftRequestVoteResp *>(p.second.get());
            auto *ae  = dynamic_cast<RaftAppendEntries *>(p.second.get());
            auto *aer = dynamic_cast<RaftAppendEntriesResp *>(p.second.get());
            int r     = 0;

            assert(replicas.count(p.first));
            if (!replicas[p.first]->up()) {
                /* Replica is currently down, we just drop this message.
                 * In case of append entries message, we modify it to pretend
                 * it's an heartbeat, so that it's not considered an
                 * interesting event in the check below. */
                if (ae) {
                    ae->entries.clear();
                }
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

            /* All messages are interesting events, except for heartbeats. */
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
                    (t + cmd.milliseconds).count(),
                    dynamic_cast<TestReplica *>(cmd.sm), cmd.type));
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
                    cout << "Submitting command " << next.cmd << " to "
                         << leader->local_name() << endl;
                    if (leader->submit(
                            reinterpret_cast<const char *>(&next.cmd), nullptr,
                            &output_next)) {
                        return -1;
                    }
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
                    if (e.is_interesting() &&
                        (next.event_type == TestEventType::SMFailure ||
                         e.event_type == TestEventType::ClientRequest)) {
                        e.abstime += chrono::milliseconds(200);
                    }
                }
                events.sort();
            }
        }

        /* Update time and Raft state machine output. */
        t      = t_next;
        output = std::move(output_next);

        /* In case this should be the last iteration, check if any
         * retransmissions are needed, and schedule them. */
        if (retransmit_check && should_stop(t_last_ievent + grace_period)) {
            const TestReplica *const leader = get_leader();
            set<uint32_t> missing_commands;

            if (leader) {
                missing_commands = leader->get_missing_commands(
                    std::move(missing_commands), input_counter);
            }
            for (const auto cmd : missing_commands) {
                TestEvent se =
                    TestEvent::CreateRequestEvent(t_next.count() + 1);
                se.cmd = cmd;
                events.push_back(se);
                cout << "Retransmit client request " << cmd << endl;
            }

            /* No need to keep checking. */
            retransmit_check = false;
        }
    }

    /* Make sure that the list of committed commands is the same for all the
     * replicas and that no command is missing. Commands may have been
     * committed in a different order from the original, because requests
     * may have been discarded (e.g. because of log conflicts) and
     * retransmitted. In any case, the order must be consistent across
     * replicas. */
    const TestReplica *prev = nullptr;
    assert(replicas.size() > 0);
    for (const auto &kv : replicas) {
        if (kv.second->up()) {
            if (!prev) {
                /* On the first active replica, check that there are no missing
                 * commands. */
                set<uint32_t> missing_commands =
                    kv.second->get_missing_commands(set<uint32_t>(),
                                                    input_counter);

                for (const auto cmd : missing_commands) {
                    cout << "Replica " << kv.first << " misses command " << cmd
                         << endl;
                    return 1;
                }
            } else if (!prev->cross_check(*kv.second.get())) {
                /* On any other replica just check that the list of committed
                 * commands is the same of the previous checked replica. */
                cout << "Check failed for replica " << kv.first << endl;
                return 1;
            }
            prev = kv.second.get();
        }
    }

    return 0;
}

/*
 * Test vectors for the Raft implementation. A current limitation is that all
 * tests are positive. Each test vector is crafted in such a way that a majority
 * of the replicas is eventually available (although there can be periods with
 * no majority, or even zero active replicas).
 */
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
        /* (1) No failures, one request. */
        {Req(400)},
        /* (2) No failures. */
        {Req(240), Req(411), Req(600), Req(600), Req(601), Req(602), Req(658),
         Req(661), Req(721)},
        /* (3) Two follower failures, no respawn. */
        {Req(350), Req(360), Fail(365, F, 0), Req(370), Req(450),
         Fail(450, F, 1), Req(454), Req(455), Req(550), Req(560)},
        /* (4) One follower failure with immediate respawn. */
        {Req(301), Req(302), Fail(303, F, 0), Respawn(305, 0), Req(307),
         Req(309)},
        /* (5) One follower failure with respawn after some time. */
        {Req(301), Req(302), Fail(303, F, 0), Req(307), Req(309), Req(313),
         Respawn(500, 0), Req(600)},
        /* (6) Leader failure with no respawn. */
        {Req(350), Req(355), Fail(359, L, 0), Req(450), Req(370), Req(454),
         Req(455), Req(550), Req(560)},
        /* (7) Leader failure with respawn. */
        {Req(350), Req(355), Fail(359, L, 0), Req(450), Req(370),
         Respawn(570, 0), Req(601), Req(608)},
        /* (8) Late failure of a follower with respawn. */
        {Req(376), Req(698), Fail(700, F, 0), Req(710), Respawn(750, 0)},
        /* (9) Too many failures to commit, then one respawn. */
        {Req(300), Req(300), Fail(350, F, 0), Req(351), Fail(600, F, 1),
         Req(610), Fail(611, F, 2), Req(640), Respawn(800, 1), Req(820)},
        /* (10) Same as (9), with everyone recoverying. */
        {Req(300), Req(300), Fail(350, F, 0), Req(351), Fail(600, F, 1),
         Req(610), Fail(611, F, 2), Req(640), Respawn(800, 1), Req(801),
         Respawn(802, 0), Respawn(804, 2), Req(810)},
        /* (11) Three failing leaders in a row, then respawn of one
         * of them. */
        {Req(500), Fail(500, L, 0), Req(1000), Fail(1000, L, 1), Req(1500),
         Fail(1501, L, 2), Req(2000), Req(2001), Respawn(2100, 2)},
        /* (12) Three failing leaders in a row, then respawn of all of
         * them. */
        {Req(500), Fail(500, L, 0), Req(1000), Fail(1000, L, 1), Req(1500),
         Fail(1501, L, 2), Req(2000), Req(2001), Respawn(2100, 0),
         Respawn(2100, 1), Respawn(2100, 2), Req(2500)},
        /* (13) Loop where in each iteration a leader fails, the previously
         * failed one respawns, and a new request arrives. */
        {Req(300),         Fail(310, L, 0),  Fail(1000, L, 1), Respawn(1000, 0),
         Req(1000),        Fail(2000, L, 2), Respawn(2000, 1), Req(2000),
         Fail(3000, L, 3), Respawn(3000, 2), Req(3000),        Fail(4000, L, 4),
         Respawn(4000, 3), Req(4000),        Fail(5000, L, 5), Respawn(5000, 4),
         Req(5000),        Fail(6000, L, 6), Respawn(6000, 5), Req(6000),
         Fail(7000, L, 7), Respawn(7000, 6), Req(7000)},
        /* (14) Two follower fail while request arrives, causing partial
         * replication of an entry. Then the leader fails together with an
         * additional follower and the previous two failing follower respawn. */
        {Req(600), Fail(600, F, 0), Fail(600, F, 1), Fail(700, L, 2),
         Fail(700, F, 3), Req(700), Respawn(700, 0), Respawn(700, 1)},
        /* (15) Request arrives to the leader, and at the same time all the
         * followers fail, so that only the leader has the request in its log.
         * Then the leader fails and all the followers recover, electing a new
         * leader and servicing a new request. When the first leader recovers
         * later, there is a conflict between its log and the other logs. */
        {Req(600), Fail(600, F, 0), Fail(600, F, 1), Fail(600, F, 2),
         Fail(600, F, 3), Fail(650, L, 4), Respawn(700, 0), Respawn(700, 1),
         Respawn(700, 2), Respawn(700, 3), Req(700), Respawn(1300, 4)},
        /* (16) Similar to (15). Start with committing a double request, then
         * all the four followers fail together (on the request), and the leader
         * fails shortly after.
         * The four followers respawn and elect a new leader, but on the next
         * request a similar failure happen again (the three followers fail,
         * the second leader fails shortly after and the three followers
         * respawn to elect a new leader). When the two failed leaders respawn
         * later they'll have inconsistent logs.
         */
        {Req(550),         Req(550),         Req(700),
         Fail(700, F, 0),  Fail(700, F, 1),  Fail(700, F, 2),
         Fail(700, F, 3),  Fail(750, L, 4),  Respawn(800, 0),
         Respawn(800, 1),  Respawn(800, 2),  Respawn(800, 3),
         Req(1500),        Fail(1500, F, 5), Fail(1500, F, 6),
         Fail(1500, F, 7), Fail(1550, L, 8), Respawn(1600, 5),
         Respawn(1600, 6), Respawn(1600, 7), Req(1700),
         Req(1700),        Respawn(1710, 4), Respawn(1710, 8)}};
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
