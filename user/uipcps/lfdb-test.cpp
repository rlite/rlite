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

using NextHops = std::unordered_map<rlite::NodeId, std::list<rlite::NodeId>>;

struct TestLFDB : public rlite::LFDB {
    using LinksList = std::vector<std::pair<int, int>>;
    LinksList links;

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

    bool reachable(int src_node, int dst_node, int n)
    {
        std::string src = std::to_string(src_node);
        std::string dst = std::to_string(dst_node);
        std::string cur = src;

        for (; n >= 0; n--) {
        }
        return true;
    }
};

static void
usage()
{
    std::cout << "lfdb-test -n SIZE\n"
                 "          -v be verbose\n"
                 "          -h show this help and exit\n";
}

int
main(int argc, char **argv)
{
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

    std::list<TestLFDB::LinksList> test_vectors = {
        {{0, 2}, {0, 3}, {0, 4}, {2, 4}, {3, 4}}};

    {
        /* Grid-shaped network of size NxN. */
        TestLFDB::LinksList links;
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

        test_vectors.push_back(std::move(links));
    }

    int counter = 1;
    for (const auto &links : test_vectors) {
        std::cout << "Test vector #" << counter++ << std::endl;

        TestLFDB lfdb(links, /*lfa_enabled=*/false);

        if (verbosity) {
            std::stringstream ss;
            lfdb.dump(ss);
            std::cout << ss.str();
        }
        assert(!links.empty());

        std::unordered_map<rlite::NodeId, NextHops> rtables;

        auto start = std::chrono::system_clock::now();
        for (const auto &kv : lfdb.db) {
            const rlite::NodeId &source = kv.first;

            lfdb.compute_next_hops(source);
            if (verbosity) {
                std::stringstream ss;
                lfdb.dump_routing(ss, source);
                std::cout << ss.str();
            }
            rtables[source] = std::move(lfdb.next_hops);
        }
        auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now() - start);

        std::cout << "Completed in " << delta.count() << " ms" << std::endl;
    }

    return 0;
}
