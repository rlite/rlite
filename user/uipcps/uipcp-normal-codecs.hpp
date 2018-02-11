/*
 * Serialization of RIB objects.
 *
 * Copyright (C) 2015-2016 Nextworks
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

#ifndef __UIPCP_CODECS_H__
#define __UIPCP_CODECS_H__

#include <stdint.h>
#include <list>
#include <string>
#include <memory>

#include "rlite/common.h"
#include "rina/cdap.hpp"

#ifdef RL_MEMTRACK
#define rl_new(_exp, _ty)                                                      \
    ({                                                                         \
        rl_mt_adjust(1, _ty);                                                  \
        new _exp;                                                              \
    })
#define rl_delete(_exp, _ty)                                                   \
    do {                                                                       \
        rl_mt_adjust(-1, _ty);                                                 \
        delete _exp;                                                           \
    } while (0)
#else /* RL_MEMTRACK */
#define rl_new(_exp, _ty) new _exp
#define rl_delete(_exp, _ty) delete _exp
#endif /* RL_MEMTRACK */

using NodeId = std::string;

/* Helper for pretty printing of default route. */
static inline std::string
node_id_pretty(const NodeId &node)
{
    if (node == std::string()) {
        return std::string("any");
    }
    return node;
}

struct UipcpObject {
    virtual int serialize(char *buf, unsigned int size) const = 0;
    virtual ~UipcpObject() {}
};

struct EnrollmentInfo : public UipcpObject {
    rlm_addr_t address = RL_ADDR_NULL;
    std::list<std::string> lower_difs;
    bool start_early = false;

    EnrollmentInfo() = default;
    EnrollmentInfo(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct RinaName {
    std::string apn;
    std::string api;
    std::string aen;
    std::string aei;

    RinaName() = default;
    RinaName(const std::string &apn_, const std::string &api_,
             const std::string &aen_, const std::string &aei_);
    RinaName(const struct rina_name *name);
    RinaName(const char *name);
    RinaName(const std::string &name);
    operator std::string() const;
    bool operator==(const RinaName &other) const;
    bool operator!=(const RinaName &other) const;
    int rina_name_fill(struct rina_name *name);
};

struct DFTEntry : public UipcpObject {
    RinaName appl_name;
    std::string ipcp_name;
    uint64_t timestamp = 0;
    /* Not externally visible (not serialized), true
     * if this entry refers to an application registered
     * locally. */
    bool local = false;

    DFTEntry() = default;
    DFTEntry(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct DFTSlice : public UipcpObject {
    std::list<DFTEntry> entries;

    DFTSlice() = default;
    DFTSlice(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct NeighborCandidate : public UipcpObject {
    std::string apn;
    std::string api;
    std::string aen; /* not serialized */
    std::string aei; /* not serialized */
    rlm_addr_t address = RL_ADDR_NULL;
    std::list<std::string> lower_difs;

    NeighborCandidate() = default;
    NeighborCandidate(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;

    bool operator==(const NeighborCandidate &o) const;
    bool operator!=(const NeighborCandidate &o) const { return !(*this == o); }
};

struct NeighborCandidateList : public UipcpObject {
    std::list<NeighborCandidate> candidates;

    NeighborCandidateList() = default;
    NeighborCandidateList(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct LowerFlow : public UipcpObject {
    NodeId local_node;
    NodeId remote_node;
    unsigned int cost   = 0;
    unsigned int seqnum = 0;
    bool state          = false;
    unsigned int age    = 0;

    LowerFlow() = default;
    RL_COPIABLE_MOVABLE(LowerFlow);
    LowerFlow(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
    bool operator==(const LowerFlow &o)
    {
        /* Don't use seqnum and age for the comparison. */
        return local_node == o.local_node && remote_node == o.remote_node &&
               cost == o.cost;
    }
    bool operator!=(const LowerFlow &o) { return !(*this == o); }

    operator std::string() const;
};

struct LowerFlowList : public UipcpObject {
    std::list<LowerFlow> flows;

    LowerFlowList() = default;
    LowerFlowList(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct Property : public UipcpObject {
    std::string name;
    std::string value;

    Property() = default;
    Property(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct PolicyDescr : public UipcpObject {
    std::string name;
    std::string impl_name;
    std::string version;
    std::list<Property> parameters;

    PolicyDescr() = default;
    PolicyDescr(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct AData : public UipcpObject {
    rlm_addr_t src_addr;
    rlm_addr_t dst_addr;
    std::unique_ptr<CDAPMessage> cdap;

    AData() = default;
    AData(const char *buf, unsigned int size);
    ~AData() = default;
    int serialize(char *buf, unsigned int size) const override;
};

struct AddrAllocRequest : public UipcpObject {
    rlm_addr_t requestor = RL_ADDR_NULL;
    rlm_addr_t address   = RL_ADDR_NULL;
    bool pending         = true; /* not serialized */

    AddrAllocRequest() = default;
    AddrAllocRequest(rlm_addr_t a, rlm_addr_t r)
        : requestor(r), address(a), pending(true)
    {
    }
    AddrAllocRequest(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct AddrAllocEntries : public UipcpObject {
    std::list<AddrAllocRequest> entries;

    AddrAllocEntries() = default;
    AddrAllocEntries(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct RaftRequestVote : public UipcpObject {
    uint32_t term;
    std::string candidate_id;
    uint32_t last_log_index;
    uint32_t last_log_term;

    RaftRequestVote() = default;
    RaftRequestVote(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct RaftRequestVoteResp : public UipcpObject {
    uint32_t term;
    bool vote_granted;

    RaftRequestVoteResp() = default;
    RaftRequestVoteResp(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct RaftAppendEntries : public UipcpObject {
    uint32_t term;
    std::string leader_id;
    uint32_t leader_commit;
    uint32_t prev_log_index;
    uint32_t prev_log_term;
    size_t EntrySize = 0; /* not serialized */
    std::list<std::pair<uint32_t, std::unique_ptr<char[]>>> entries;

    RaftAppendEntries() = default;
    RaftAppendEntries(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct RaftAppendEntriesResp : public UipcpObject {
    uint32_t term;
    std::string follower_id;
    uint32_t log_index;
    bool success;

    RaftAppendEntriesResp() = default;
    RaftAppendEntriesResp(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

#endif /* __UIPCP_CODECS_H__ */
