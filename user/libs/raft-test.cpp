#include <iostream>
#include <list>
#include <string>
#include <cstdint>
#include <cassert>
#include <cstring>

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

int
main()
{
    list<string> names = {"r1", "r2", "r3", "r4", "r5"};
    map<string, TestReplica> replicas;

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
        if (sm->init(peers, NULL)) {
            goto out;
        }
        replicas[local] = TestReplica(sm);
    }

    {
        string input;
        cin >> input;
    }

out:
    for (const auto &kv : replicas) {
        kv.second.sm->shutdown();
    }
    replicas.clear();

    return 0;
}
