#include <iostream>
#include <list>
#include <string>
#include <cstdint>
#include <cassert>
#include <cstring>
#include <functional>
#include <queue>

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
    unsigned int abstime;
    RaftTimerType ttype;

    TestEvent(unsigned int t, RaftTimerType ty) : abstime(t), ttype(ty) {}

    bool operator<(const TestEvent &o) const { return abstime < o.abstime; }
    bool operator>=(const TestEvent &o) const { return !(*this < o); }
};

int
main()
{
    list<string> names = {"r1", "r2", "r3", "r4", "r5"};
    map<string, TestReplica *> replicas;
    priority_queue<TestEvent> events;
    unsigned int t = 0; /* time */
    RaftSMOutput output;

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
        /* Process timer commands. */
        for (const RaftTimerCmd &cmd : output.timer_commands) {
            if (cmd.action == RaftTimerAction::Set) {
                events.push(TestEvent(t + cmd.milliseconds, cmd.type));
            }
        }
        {
            string input;
            cin >> input;
        }
        break;
    }

out:
    for (const auto &kv : replicas) {
        kv.second->sm->shutdown();
        delete kv.second;
    }

    return 0;
}
