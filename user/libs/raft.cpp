/*
 * An implementation of the RAFT protocol.
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

#include "rlite/raft.hpp"
#include <cassert>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

using namespace std;

int
RaftSM::Init(const string& logfilename)
{
    /* If logfile does not exists it means that this is the first time
     * this replica boots. */
    bool first_boot = !ifstream(logfilename).good();

    logfile.open(logfilename, ios::in | ios::out | ios::binary);
    if (logfile.fail()) {
        return -1;
    }
    if (first_boot) {
        /* Initialize the log header. Write an 8 byte magic
         * number, an 8 bytes current_term and a NULL voted_for. */
    }

    return 0;
}

RaftSM::~RaftSM() {
    if (logfile.is_open()) {
        logfile.close();
    }
}

int
RaftSM::RequestVoteInput(const RaftRequestVote &msg, RaftSMOutput *out)
{
    assert(out);
    return 0;
}

int
RaftSM::RequestVoteRespInput(const RaftRequestVote &msg, RaftSMOutput *out)
{
    assert(out);
    return 0;
}

int
RaftSM::AppendEntriesInput(const RaftAppendEntries &msg, RaftSMOutput *out)
{
    assert(out);
    return 0;
}

int
RaftSM::AppendEntriesRespInput(const RaftAppendEntries &msg, RaftSMOutput *out)
{
    assert(out);
    return 0;
}

int
RaftSM::TimerExpired(RaftTimerType, RaftSMOutput *out)
{
    assert(out);
    return 0;
}
