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

#include "rlite/raft.hpp"

using namespace std;

struct TestLogEntry : public RaftLogEntry {
    uint32_t command;

    void serialize(char *serbuf) const override
    {
        memcpy(serbuf, reinterpret_cast<const char *>(&term), sizeof(term));
        memcpy(serbuf, reinterpret_cast<const char *>(&command),
               sizeof(command));
    }

    static size_t size() { return sizeof(Term) + sizeof(uint32_t); }
};

static string
logfile(const string &replica)
{
    return string("/tmp/raft_test_") + replica + "_log";
}

struct TestReplica {
    RaftSM *sm = nullptr;

    TestReplica() = default;
    TestReplica(RaftSM *_sm) : sm(_sm) {}
    ~TestReplica()
    {
        if (sm) {
            delete sm;
        }
    }
};

struct TestEvent {
    unsigned int abstime = 0;
    RaftSM *sm           = nullptr;
    RaftTimerType ttype  = RaftTimerType::Invalid;

    TestEvent(unsigned int t, RaftSM *_sm, RaftTimerType ty)
        : abstime(t), sm(_sm), ttype(ty)
    {
    }

    bool operator<(const TestEvent &o) const { return abstime < o.abstime; }
    bool operator>=(const TestEvent &o) const { return !(*this < o); }
};

int
main()
{
    list<string> names = {"r1", "r2", "r3", "r4", "r5"};
    map<string, TestReplica *> replicas;
    list<TestEvent> events;
    unsigned int t = 0; /* time */
    RaftSMOutput output;

    srand(time(0));

    /* Clean up leftover logfiles, if any. */
    for (const auto &local : names) {
        remove(logfile(local).c_str());
    }

    for (const auto &local : names) {
        string logfilename = logfile(local);
        list<string> peers;
        RaftSM *sm;

        for (const auto &peer : names) {
            if (peer != local) {
                peers.push_back(peer);
            }
        }

        sm = new RaftSM(local + "-sm", local, logfilename, TestLogEntry::size(),
                        std::cerr, std::cout);
        if (sm->init(peers, &output)) {
            goto out;
        }
        replicas[local] = new TestReplica(sm);
    }

    for (;;) {
        unsigned int t_next = t + 1;
        RaftSMOutput output_next;

        cout << "| t = " << t << " |" << endl;

        /* Process current output messages. */
        for (const auto &p : output.output_messages) {
            auto *rv  = dynamic_cast<RaftRequestVote *>(p.second);
            auto *rvr = dynamic_cast<RaftRequestVoteResp *>(p.second);
            auto *ae  = dynamic_cast<RaftAppendEntries *>(p.second);
            auto *aer = dynamic_cast<RaftAppendEntriesResp *>(p.second);

            assert(replicas.count(p.first));
            if (rv) {
                replicas[p.first]->sm->request_vote_input(*rv, &output_next);
            } else if (rvr) {
                replicas[p.first]->sm->request_vote_resp_input(*rvr,
                                                               &output_next);
            } else if (ae) {
                replicas[p.first]->sm->append_entries_input(*ae, &output_next);
            } else if (aer) {
                replicas[p.first]->sm->append_entries_resp_input(*aer,
                                                                 &output_next);
            } else {
                assert(false);
            }

            delete p.second;
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
                events.push_back(
                    TestEvent(t + cmd.milliseconds, cmd.sm, cmd.type));
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
            next.sm->timer_expired(next.ttype, &output_next);
            events.pop_front();
        }
        t      = t_next;
        output = output_next;

        {
            string input;
            cin >> input;
        }
    }

out:
    for (const auto &kv : replicas) {
        kv.second->sm->shutdown();
        delete kv.second;
    }

    return 0;
}
