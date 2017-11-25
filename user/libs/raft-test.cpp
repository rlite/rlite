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

int
main()
{
    list<string> replicas = {"r1", "r2", "r3", "r4", "r5"};
    list<RaftSM *> sms;

    cout << TestLogEntry::size() << endl;

    for (const auto &local : replicas) {
        string logfilename = string("/tmp/raft_test_") + local + "_log";
        list<string> peers;
        RaftSM *sm;

        for (const auto &peer : replicas) {
            if (peer != local) {
                peers.push_back(peer);
            }
        }

        sm = new RaftSM(string("test-sm"), local, logfilename,
                        TestLogEntry::size(), std::cerr, std::cout);
        if (sm->init(peers, NULL)) {
            goto out;
        }
        sms.push_back(sm);
    }

out:
    for (auto sm : sms) {
        sm->shutdown();
        delete sm;
    }

    return 0;
}
