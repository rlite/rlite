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
    uint32_t output_counter = 18;

public:
    TestReplica() = default;
    RL_NONCOPIABLE(TestReplica);
    TestReplica(const std::string &smname, const ReplicaId &myname,
                std::string logname)
        : RaftSM(smname, myname, logname,
                 /*cmd_size=*/sizeof(uint32_t), std::cerr, std::cout)
    {
    }
    ~TestReplica() { shutdown(); }
    virtual int apply(const char *const serbuf) override
    {
        uint32_t cmd = *(reinterpret_cast<const uint32_t *>(serbuf));
        if (++output_counter != cmd) {
            cout << "Mismatch: expected " << output_counter << ", got " << cmd
                 << endl;
            return -1;
        }
        return 0;
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
    RaftSM *sm           = nullptr;
    RaftTimerType ttype  = RaftTimerType::Invalid;

    bool operator<(const TestEvent &o) const { return abstime < o.abstime; }
    bool operator>=(const TestEvent &o) const { return !(*this < o); }

    static uint32_t get_next_command() { return ++input_counter; }

    static TestEvent CreateTimerEvent(unsigned int t, RaftSM *_sm,
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

    static TestEvent CreateFailureEvent(unsigned int t, RaftSM *_sm)
    {
        TestEvent e;
        e.event_type = TestEventType::SMFailure;
        e.abstime    = t;
        e.sm         = _sm;
        return e;
    }

    static TestEvent CreateRespawnEvent(unsigned int t, RaftSM *_sm)
    {
        TestEvent e;
        e.event_type = TestEventType::SMRespawn;
        e.abstime    = t;
        e.sm         = _sm;
        return e;
    }

private:
    static uint32_t input_counter;
};

uint32_t TestEvent::input_counter = 18;

int
main()
{
    list<string> names = {"r1", "r2", "r3", "r4", "r5"};
    map<string, std::unique_ptr<RaftSM>> replicas;
    list<TestEvent> events;
    unsigned int t           = 0; /* time */
    const unsigned int t_max = 500;
    RaftSMOutput output;

    srand(time(0));

    /* Clean up leftover logfiles, if any. */
    for (const auto &local : names) {
        remove(logfile(local).c_str());
    }

    /* Push some client submission. */
    events.push_back(TestEvent::CreateRequestEvent(350));
    events.push_back(TestEvent::CreateRequestEvent(360));
    events.push_back(TestEvent::CreateRequestEvent(370));
    events.sort();

    for (const auto &local : names) {
        string logfilename = logfile(local);
        list<string> peers;
        std::unique_ptr<RaftSM> sm;

        for (const auto &peer : names) {
            if (peer != local) {
                peers.push_back(peer);
            }
        }

        sm = make_unique<TestReplica>(
            /*smname=*/local + "-sm", /*myname=*/local, logfilename);
        if (sm->init(peers, &output)) {
            return -1;
        }
        replicas[local] = std::move(sm);
    }

    while (t <= t_max) {
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
            if (rv) {
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
                    t + cmd.milliseconds, cmd.sm, cmd.type));
                events.sort();
            } else {
                assert(cmd.action == RaftTimerAction::Stop);
            }
        }

        /* Process all the timers expired so far, updating the associated
         * Raft state machine. */
        while (!events.empty()) {
            const TestEvent &next = events.front();
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
                if (next.sm->timer_expired(next.ttype, &output_next)) {
                    return -1;
                }
                break;
            }

            case TestEventType::ClientRequest: {
                /* This event is a client submission. */
                bool submitted = false;
                for (const auto &kv : replicas) {
                    if (kv.second->leader()) {
                        LogIndex request_id;
                        uint32_t cmd = TestEvent::get_next_command();

                        if (kv.second->submit(reinterpret_cast<char *>(&cmd),
                                              &request_id, &output_next)) {
                            return -1;
                        }
                        submitted = true;
                        cout << "Command " << cmd << " submitted" << endl;
                    }
                }
                if (!submitted) {
                    cout << "Dropped client request (no leader)" << endl;
                }
            }
            case TestEventType::SMFailure: {
                break;
            }
            case TestEventType::SMRespawn: {
                break;
            }
            }
            events.pop_front();
        }
        t      = t_next;
        output = std::move(output_next);
    }

    return 0;
}
