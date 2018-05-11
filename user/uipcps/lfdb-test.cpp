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
#include "uipcp-normal-lfdb.hpp"

struct TestLFDB : public rlite::LFDB {
    std::vector<std::pair<std::string, std::string>> links;

    TestLFDB(std::vector<std::pair<std::string, std::string>> links,
             bool lfa_enabled)
        : rlite::LFDB(lfa_enabled, /*verbose=*/true), links(links)
    {
        for (const auto &link : links) {
            gpb::LowerFlow lf1, lf2;

            lf1.set_local_node(link.first);
            lf1.set_remote_node(link.second);
            lf2.set_local_node(link.second);
            lf2.set_remote_node(link.first);
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

int
main()
{
    std::vector<std::pair<std::string, std::string>> links = {
        {"a", "b"}, {"a", "c"}, {"a", "d"}};

    TestLFDB lfdb(links, /*lfa_enabled=*/false);

    return lfdb.db.size();
}
