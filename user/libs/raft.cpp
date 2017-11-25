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
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

using namespace std;

int
RaftSM::init(const string &logfilename, const list<ReplicaId> peers,
             RaftSMOutput *out)
{
    /* If logfile does not exists it means that this is the first time
     * this replica boots. */
    bool first_boot = !ifstream(logfilename).good();
    int ret;

    logfile.open(logfilename, ios::in | ios::out | ios::binary);
    if (logfile.fail()) {
        return -1;
    }
    if (first_boot) {
        char null[kLogVotedForSize];

        /* Initialize the log header. Write an 4 byte magic
         * number, a 4 bytes current_term and a NULL voted_for. */
        if ((ret = log_u32_write(kLogMagicOfs, kLogMagicNumber))) {
            return ret;
        }
        if ((ret = log_u32_write(kLogCurrentTermOfs, 0U))) {
            return ret;
        }
        memset(null, 0, sizeof(null));
        if ((ret = log_buf_write(kLogVotedForOfs, null, kLogVotedForSize))) {
            return ret;
        }

    } else {
        char id_buf[kLogVotedForSize];

        /* Check the magic number and load current term and current
         * voted candidate. */
        if ((ret = magic_check())) {
            return ret;
        }
        if ((ret = log_u32_read(kLogCurrentTermOfs, &current_term))) {
            return ret;
        }
        if ((ret = log_buf_read(kLogVotedForOfs, id_buf, kLogVotedForSize))) {
            return ret;
        }
        /* Check that the 'voted_for' field on disk is null terminated. */
        auto buf_is_null_terminated = [](const char *buf, size_t len) -> bool {
            for (size_t i = 0; i < len; i++) {
                if (buf[i] == '\0') {
                    return true;
                }
            }
            return false;
        };
        if (!buf_is_null_terminated(id_buf, kLogVotedForSize)) {
            return -1;
        }
        voted_for = string(id_buf);
    }

    for (const auto &rid : peers) {
        match_index[rid] = 0;
        next_index[rid]  = 0; // TODO
    }

    return 0;
}

RaftSM::~RaftSM()
{
    if (logfile.is_open()) {
        logfile.close();
    }
}

int
RaftSM::log_u32_write(unsigned long pos, uint32_t val)
{
    logfile.seekp(pos);
    if (logfile.fail()) {
        return -1;
    }
    logfile.write(reinterpret_cast<const char *>(&val), sizeof(val));
    if (logfile.fail()) {
        return -1;
    }
    return 0;
}

int
RaftSM::log_u32_read(unsigned long pos, uint32_t *val)
{
    logfile.seekg(pos);
    if (logfile.fail() || logfile.eof()) {
        return -1;
    }
    logfile.read(reinterpret_cast<char *>(val), sizeof(*val));
    if (logfile.fail() || logfile.eof()) {
        return -1;
    }
    return 0;
}

int
RaftSM::magic_check()
{
    uint32_t magic = 0;

    if (log_u32_read(kLogMagicOfs, &magic)) {
        return -1;
    }
    return (magic != kLogMagicNumber) ? -1 : 0;
}

int
RaftSM::log_buf_write(unsigned long pos, const char *buf, size_t len)
{
    logfile.seekp(pos);
    if (logfile.fail()) {
        return -1;
    }
    logfile.write(buf, len);
    if (logfile.fail()) {
        return -1;
    }
    return 0;
}

int
RaftSM::log_buf_read(unsigned long pos, char *buf, size_t len)
{
    logfile.seekg(pos);
    if (logfile.fail() || logfile.eof()) {
        return -1;
    }
    logfile.read(buf, len);
    if (logfile.fail() || logfile.eof()) {
        return -1;
    }
    return 0;
}

int
RaftSM::request_vote_input(const RaftRequestVote &msg, RaftSMOutput *out)
{
    assert(out);
    return 0;
}

int
RaftSM::request_vote_resp_input(const RaftRequestVote &msg, RaftSMOutput *out)
{
    assert(out);
    return 0;
}

int
RaftSM::append_entries_input(const RaftAppendEntries &msg, RaftSMOutput *out)
{
    assert(out);
    return 0;
}

int
RaftSM::append_entries_resp_input(const RaftAppendEntries &msg,
                                  RaftSMOutput *out)
{
    assert(out);
    return 0;
}

int
RaftSM::timer_expired(RaftTimerType, RaftSMOutput *out)
{
    assert(out);
    return 0;
}
