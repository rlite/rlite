/*
 * Tests for the next hop computation (LFDB) using bandwidth reservation
 * policies.
 *
 * Copyright (C) 2018 Vincenzo Maffione
 * Authors: Vincenzo Maffione <v.maffione@gmail.com>
 *         Michal Koutenský <koutak.m@gmail.com>
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
#include <sstream>
#include <list>
#include <vector>
#include <cassert>
#include <chrono>
#include <unistd.h>
#include <cmath>

#include "uipcp-normal-lfdb.hpp"

/* A type to represent a single routing table, excluding the default next
 * hop. */
using NextHops = std::unordered_map<rlite::NodeId, std::vector<rlite::NodeId>>;

/* A type to represent a collection of routing tables, one for each node
 * in a network. */
using RoutingTables =
    std::unordered_map<rlite::NodeId, std::pair<NextHops, rlite::NodeId>>;

/* Representation of a list of reachability tests. See the description
 * below. */
using ReachabilityTest  = std::tuple<int, int, int, bool>;
using ReachabilityTests = std::vector<ReachabilityTest>;

struct TestLFDB : public rlite::LFDB {
    using Link      = std::tuple<int, int, int>;
    using LinksList = std::vector<Link>;
    LinksList links;

    /* Populate rlite::LFDB::db from the list of links coming from
     * the test vector. */
    TestLFDB(const LinksList &links, bool lfa_enabled)
        : rlite::LFDB(lfa_enabled, /*verbose=*/true), links(links)
    {
        for (const auto &link : links) {
            gpb::LowerFlow lf1, lf2;

            lf1.set_local_node(std::to_string(std::get<0>(link)));
            lf1.set_remote_node(std::to_string(std::get<1>(link)));
            lf2.set_local_node(std::to_string(std::get<1>(link)));
            lf2.set_remote_node(std::to_string(std::get<0>(link)));
            lf1.set_cost(1);
            lf2.set_cost(1);
            lf1.set_seqnum(1);
            lf2.set_seqnum(1);
            lf1.set_state(true);
            lf2.set_state(true);
            lf1.set_age(0);
            lf2.set_age(0);
            lf1.set_bw_free(std::get<2>(link));
            lf2.set_bw_free(std::get<2>(link));

            db[lf1.local_node()][lf1.remote_node()] = lf1;
            db[lf2.local_node()][lf2.remote_node()] = lf2;
        }
    }

    bool reachable(int src_node, int dest_node, const unsigned int req_flow);
};

/* Returns true if a path from * 'src_node' to 'dst_node' of at least
 * capacity 'req_flow' exists. */
bool
TestLFDB::reachable(int src_node, int dst_node, const unsigned int req_flow)
{
    rlite::NodeId dst = std::to_string(dst_node);
    rlite::NodeId cur = std::to_string(src_node);

    std::cout << "Flow " << req_flow << " from " << cur << " to " << dst
              << std::endl;
    std::vector<rlite::NodeId> result = find_flow_path(cur, dst, req_flow);

    return !result.empty();
}

int
main(int argc, char **argv)
{
    auto usage = []() {
        std::cout << "lfdb-bw-test -v be verbose\n"
                     "             -h show this help and exit\n";
    };
    int verbosity = 0;
    int opt;

    while ((opt = getopt(argc, argv, "hv:")) != -1) {
        switch (opt) {
        case 'h':
            usage();
            return 0;

        case 'v':
            verbosity++;
            break;

        default:
            std::cout << "    Unrecognized option " << static_cast<char>(opt)
                      << std::endl;
            usage();
            return -1;
        }
    }

    /* Test vectors are stored in a list of pairs. Each pair is made of
     * a list of links and a list of reachability tests. A list of links
     * describes a network graph, where nodes are integer numbers; each
     * link in the list is a tuple of integers, which represents a link
     * between two nodes and their available bandwidth. An item in list
     * of reachability tests is a tuple of integers and a bool; the first
     * integer refers to the source node, the second to the destination
     * node and the third is the requested bandwidth for the flow. The
     * boolean is the expected value of the test. Each reachability test
     * is independent and does not take into account previous tests in
     * the list. */

    std::list<std::pair<TestLFDB::LinksList, ReachabilityTests>> test_vectors =
        {{/*links=*/{TestLFDB::Link(0, 1, 10), TestLFDB::Link(0, 3, 5),
                     TestLFDB::Link(1, 2, 10), TestLFDB::Link(2, 3, 10)},
          /*reachability_tests=*/{ReachabilityTest(0, 0, 5, false),
                                  ReachabilityTest(0, 2, 5, true),
                                  ReachabilityTest(0, 3, 7, true),
                                  ReachabilityTest(0, 2, 12, false)}},
         {/*links=*/{TestLFDB::Link(0, 1, 10), TestLFDB::Link(0, 2, 5),
                     TestLFDB::Link(0, 3, 10), TestLFDB::Link(1, 4, 10),
                     TestLFDB::Link(2, 3, 5), TestLFDB::Link(2, 5, 5),
                     TestLFDB::Link(3, 4, 5), TestLFDB::Link(3, 5, 5),
                     TestLFDB::Link(4, 5, 10), TestLFDB::Link(4, 6, 5),
                     TestLFDB::Link(4, 7, 5), TestLFDB::Link(5, 6, 10),
                     TestLFDB::Link(6, 7, 10), TestLFDB::Link(7, 8, 5)},
          /*reachability_tests=*/{ReachabilityTest(3, 7, 7, true),
                                  ReachabilityTest(1, 7, 5, true)}}};

    int counter = 1;
    for (const auto &p : test_vectors) {
        TestLFDB::LinksList links            = p.first;
        ReachabilityTests reachability_tests = p.second;

        std::cout << "Test vector #" << counter << std::endl;

        /* Build the lfdb object under test by populating it with the
         * links in the test vector. */
        TestLFDB lfdb(links, /*lfa_enabled=*/false);

        if (verbosity >= 2) {
            std::stringstream ss;
            lfdb.dump(ss);
            std::cout << ss.str();
        }
        assert(!links.empty());

        /* Compute the routing tables for each node in the network and
         * store them into 'rtables'. */
        RoutingTables rtables;
        auto start = std::chrono::system_clock::now();

        for (const auto &rtest : reachability_tests) {
            if (lfdb.reachable(std::get<0>(rtest), std::get<1>(rtest),
                               std::get<2>(rtest)) != std::get<3>(rtest)) {
                std::cerr << (std::get<3>(rtest) ? "Cannot reach node "
                                                 : "Can reach node ")
                          << std::get<0>(rtest) << " from node "
                          << std::get<1>(rtest) << " with bandwidth "
                          << std::get<2>(rtest) << std::endl;
                std::cout << "Test # " << counter << " failed" << std::endl;
                return -1;
            }
        }
        auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now() - start);

        std::cout << "Test # " << counter << " completed in " << delta.count()
                  << " ms" << std::endl;
        counter++;
    }

    return 0;
}
