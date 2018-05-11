/*
 * Tests for the next hop computation (LFDB).
 *
 * Copyright (C) 2018 Vincenzo Maffione
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
using ReachabilityTests = std::vector<std::pair<int, int>>;

struct TestLFDB : public rlite::LFDB {
    using LinksList = std::vector<std::pair<int, int>>;
    LinksList links;

    /* Populate rlite::LFDB::db from the list of links coming from
     * the test vector. */
    TestLFDB(const LinksList &links, bool lfa_enabled)
        : rlite::LFDB(lfa_enabled, /*verbose=*/false), links(links)
    {
        for (const auto &link : links) {
            gpb::LowerFlow lf1, lf2;

            lf1.set_local_node(std::to_string(link.first));
            lf1.set_remote_node(std::to_string(link.second));
            lf2.set_local_node(std::to_string(link.second));
            lf2.set_remote_node(std::to_string(link.first));
            lf1.set_cost(1);
            lf2.set_cost(1);
            lf1.set_seqnum(1);
            lf2.set_seqnum(1);
            lf1.set_state(true);
            lf2.set_state(true);
            lf1.set_age(0);
            lf2.set_age(0);

            db[lf1.local_node()][lf1.remote_node()] = lf1;
            db[lf2.local_node()][lf2.remote_node()] = lf2;
        }
    }
};

/* Returns true if the routing tables are able to route a packet from
 * 'src_node' to 'dst_node' with exactly 'n' hops. */
static bool
reachable(const RoutingTables &rtables, int src_node, int dst_node,
          int expected_nhops, const bool verbose)
{
    rlite::NodeId dst = std::to_string(dst_node);
    rlite::NodeId cur = std::to_string(src_node);

    if (verbose) {
        std::cout << "---> Start from node " << cur << std::endl;
    }
    for (; expected_nhops >= 0 && cur != dst; expected_nhops--) {
        const auto &rt                 = rtables.at(cur);
        NextHops::const_iterator nhops = rt.first.find(dst);

        if (nhops != rt.first.end()) {
            /* Entry find in the routing table. */
            cur = nhops->second.front();
        } else {
            /* Not found, use default next hop. */
            cur = rt.second;
        }
        if (verbose) {
            std::cout << "     hop to " << cur << std::endl;
        }
    }
    return cur == dst && expected_nhops == 0;
}

int
main(int argc, char **argv)
{
    auto usage = []() {
        std::cout << "lfdb-test -n SIZE\n"
                     "          -v be verbose\n"
                     "          -h show this help and exit\n";
    };
    int verbosity = 0;
    int n         = 100;
    int opt;

    while ((opt = getopt(argc, argv, "hvn:")) != -1) {
        switch (opt) {
        case 'h':
            usage();
            return 0;

        case 'v':
            verbosity++;
            break;

        case 'n':
            n = std::atoi(optarg);
            break;

        default:
            std::cout << "    Unrecognized option " << static_cast<char>(opt)
                      << std::endl;
            usage();
            return -1;
        }
    }

    /* Test vectors are stored in a list of pairs. Each pair is made of a list
     * of links and a list of reachability tests. A list of links describes
     * a network graph, where nodes are integer numbers; each link in the list
     * is a pair of integers, which represents a link between two nodes. An
     * item in list of reachability tests is a pair of integers; the first
     * integer refers to a destination node to be reached (from node 0), and
     * the second integer refers to the number of expected hops to reach the
     * destination node. */
    std::list<std::pair<TestLFDB::LinksList, ReachabilityTests>> test_vectors =
        {{/*links=*/{{0, 1}, {0, 3}, {1, 2}, {2, 3}},
          /*reachability_tests=*/{{1, 1}, {2, 2}, {3, 1}}}};

    {
        /* Generate a grid-shaped network of size 'sqn' x 'sqn'. */
        TestLFDB::LinksList links;
        ReachabilityTests reachability_tests;
        int sqn = static_cast<int>(std::sqrt(n));

        if (sqn < 2) {
            sqn = 2;
        }

        auto coord = [sqn](int i, int j) { return i * sqn + j; };

        for (int i = 0; i < sqn; i++) {
            for (int j = 0; j < sqn - 1; j++) {
                links.push_back({coord(i, j), coord(i, j + 1)});
                links.push_back({coord(j, i), coord(j + 1, i)});
            }
        }

        /* Get from node 0 (top left) to top right in sqn-1 steps. */
        reachability_tests.push_back({coord(0, sqn - 1), sqn - 1});

        /* Get from node 0 (top left) to bottom left in sqn-1 steps. */
        reachability_tests.push_back({coord(sqn - 1, 0), sqn - 1});

        /* Get from node 0 (top left) to bottom right. */
        reachability_tests.push_back({coord(sqn - 1, sqn - 1), 2 * (sqn - 1)});

        /* Get from node 0 (top left) to one very close to the the
         * bottom left node. */
        reachability_tests.push_back({coord(sqn - 2, 1), sqn - 1});

        test_vectors.push_back(
            make_pair(std::move(links), std::move(reachability_tests)));
    }

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

        for (const auto &kv : lfdb.db) {
            const rlite::NodeId &source = kv.first;

            lfdb.compute_next_hops(source);
            if (verbosity >= 2) {
                std::stringstream ss;
                lfdb.dump_routing(ss, source);
                std::cout << ss.str();
            }
            rtables[source] =
                make_pair(std::move(lfdb.next_hops), std::move(lfdb.dflt_nhop));
        }
        auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now() - start);

        /* Use 'rtables' to carry out all the reachability tests defined for
         * this network. */
        for (const auto &rtest : reachability_tests) {
            const int src_node = 0;
            if (!reachable(rtables, /*src_node=*/src_node,
                           /*dst_node=*/rtest.first,
                           /*expected_nhops=*/rtest.second,
                           /*verbose=*/verbosity >= 1)) {
                std::cerr << "Cannot reach node " << rtest.first
                          << " from node " << src_node << " in " << rtest.second
                          << " steps" << std::endl;
                std::cout << "Test # " << counter << " failed" << std::endl;
                return -1;
            }
        }

        std::cout << "Test # " << counter << " completed in " << delta.count()
                  << " ms" << std::endl;
        counter++;
    }

    return 0;
}
