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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __UIPCP_CODECS_H__
#define __UIPCP_CODECS_H__

#include <stdint.h>
#include <list>
#include <string>

#include "rlite/common.h"
#include "rina/cdap.hpp"


#ifdef RL_MEMTRACK
#define rl_new(_exp, _ty)           \
        ({                          \
            rl_mt_adjust(1, _ty);   \
            new _exp;               \
        })
#define rl_delete(_exp, _ty)        \
        do {                        \
            rl_mt_adjust(-1, _ty);  \
            delete _exp;            \
        } while (0)
#else  /* RL_MEMTRACK */
#define rl_new(_exp, _ty)       new _exp
#define rl_delete(_exp, _ty)    delete _exp
#endif /* RL_MEMTRACK */

using NodeId = std::string;

/* Helper for pretty printing of default route. */
static inline std::string node_id_pretty(const NodeId& node) {
    if (node == std::string()) {
        return std::string("any");
    }
    return node;
}

struct UipcpObject {
    virtual int serialize(char *buf, unsigned int size) const = 0;
    virtual ~UipcpObject() { }
};

struct EnrollmentInfo : public UipcpObject {
    rlm_addr_t address;
    std::list< std::string > lower_difs;
    bool start_early;

    EnrollmentInfo() : address(RL_ADDR_NULL), start_early(false) { }
    EnrollmentInfo(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct RinaName {
    std::string apn;
    std::string api;
    std::string aen;
    std::string aei;

    RinaName() = default;
    RinaName(const std::string& apn_,
             const std::string& api_,
             const std::string& aen_,
             const std::string& aei_);
    RinaName(const struct rina_name *name);
    RinaName(const char *name);
    RinaName(const std::string& name);
    operator std::string() const;
    bool operator==(const RinaName& other) const;
    bool operator!=(const RinaName& other) const;
    int rina_name_fill(struct rina_name *name);
};

struct DFTEntry : public UipcpObject {
    RinaName appl_name;
    rlm_addr_t address;
    uint64_t timestamp;
    /* Not externally visible (not serialized), true
     * if this entry refers to an application registered
     * locally. */
    bool local;

    DFTEntry() : address(RL_ADDR_NULL), timestamp(0), local(false) { }
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
    rlm_addr_t address;
    std::list<std::string> lower_difs;

    NeighborCandidate() = default;
    NeighborCandidate(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;

    bool operator==(const NeighborCandidate &o) const;
    bool operator!=(const NeighborCandidate &o) const {
        return !(*this == o);
    }
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
    unsigned int cost;
    unsigned int seqnum;
    bool state;
    unsigned int age;

    LowerFlow() : cost(0), seqnum(0), state(false), age(0) { }
    LowerFlow(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
    bool operator==(const LowerFlow& o) {
        /* Don't use seqnum and age for the comparison. */
        return local_node == o.local_node && remote_node == o.remote_node &&
                cost == o.cost;
    }
    bool operator!=(const LowerFlow& o) {
        return !(*this == o);
    }

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

struct QosSpec : public UipcpObject {
    std::string name;
    uint32_t qos_id;
    uint64_t avg_bw;
    uint64_t avg_sdu_bw;
    uint64_t peak_bw_duration;
    uint64_t peak_sdu_bw_duration;
    double undetected_bit_error_rate;
    bool partial_delivery; /* carries msg_boundaries */
    bool in_order_delivery;
    int32_t max_sdu_gap;
    uint32_t delay;
    uint32_t jitter;
    std::list<Property> extra_parameters;

    QosSpec() = default;
    QosSpec(const char *buf, unsigned int size);
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

struct WindowBasedFlowCtrlConfig : public UipcpObject {
    rlm_seq_t max_cwq_len; /* closed window queue */
    rlm_seq_t initial_credit;
    PolicyDescr rcvr_flow_ctrl;
    PolicyDescr tx_ctrl;

    WindowBasedFlowCtrlConfig() = default;
    WindowBasedFlowCtrlConfig(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct RateBasedFlowCtrlConfig : public UipcpObject {
    uint64_t sending_rate;
    uint64_t time_period; /* us */
    PolicyDescr no_rate_slow_down;
    PolicyDescr no_override_default_peak;
    PolicyDescr rate_reduction;

    RateBasedFlowCtrlConfig() = default;
    RateBasedFlowCtrlConfig(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct FlowCtrlConfig : public UipcpObject {
    uint8_t fc_type;
    WindowBasedFlowCtrlConfig win;
    RateBasedFlowCtrlConfig rate;
    uint64_t sent_bytes_th;
    uint64_t sent_bytes_perc_th;
    uint64_t sent_buffer_th;
    uint64_t rcv_bytes_th;
    uint64_t rcv_bytes_perc_th;
    uint64_t rcv_buffers_th;
    PolicyDescr closed_win;
    PolicyDescr flow_ctrl_overrun;
    PolicyDescr reconcile_flow_ctrl;
    PolicyDescr receiving_flow_ctrl;

    FlowCtrlConfig() = default;
    FlowCtrlConfig(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct RtxCtrlConfig : public UipcpObject {
    uint32_t max_time_to_retry; /* R div initial_tr */
    uint16_t data_rxmsn_max;
    uint32_t initial_tr;

    PolicyDescr rtx_timer_expiry;
    PolicyDescr sender_ack;
    PolicyDescr receiving_ack_list;
    PolicyDescr rcvr_ack;
    PolicyDescr sending_ack;
    PolicyDescr rcvr_ctrl_ack;

    RtxCtrlConfig() = default;
    RtxCtrlConfig(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct DtcpConfig : public UipcpObject {
    bool flow_ctrl;
    FlowCtrlConfig flow_ctrl_cfg;
    bool rtx_ctrl;
    RtxCtrlConfig rtx_ctrl_cfg;
    PolicyDescr lost_ctrl_pdu;
    PolicyDescr rtt_estimator;

    DtcpConfig() = default;
    DtcpConfig(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct ConnPolicies : public UipcpObject {
    bool dtcp_present;
    DtcpConfig dtcp_cfg;
    rlm_seq_t seq_num_rollover_th;
    uint32_t initial_a_timer;
    PolicyDescr rcvr_timer_inact;
    PolicyDescr sender_timer_inact;
    PolicyDescr init_seq_num;

    ConnPolicies() = default;
    ConnPolicies(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct ConnId : public UipcpObject {
    uint32_t qos_id;
    uint32_t src_cep;
    uint32_t dst_cep;

    ConnId() : qos_id(0), src_cep(0), dst_cep(0) { }
    ConnId(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct FlowRequest : public UipcpObject {
    RinaName src_app;
    RinaName dst_app;
    rl_port_t src_port;
    rl_port_t dst_port;
    rlm_addr_t src_addr;
    rlm_addr_t dst_addr;
    std::list<ConnId> connections;
    uint32_t cur_conn_idx;
    uint32_t state;
    QosSpec qos;
    ConnPolicies policies;
    void *access_ctrl;
    uint32_t max_create_flow_retries;
    uint32_t create_flow_retries;
    uint32_t hop_cnt;

     /* Local storage. */
    int invoke_id;
    uint32_t uid;
    struct rl_flow_config flowcfg;
#define RL_FLOWREQ_INITIATOR    0x1 /* Was I the initiator? */
#define RL_FLOWREQ_SEND_DEL     0x2 /* Should I send a delete message ? */
    uint8_t flags;
    /* End of local storage. */

    FlowRequest() : access_ctrl(NULL), flags(0) { }
    FlowRequest(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct AData : public UipcpObject {
    rlm_addr_t src_addr;
    rlm_addr_t dst_addr;
    CDAPMessage *cdap;

    AData() : cdap(NULL) { }
    AData(const char *buf, unsigned int size);
    ~AData() { if (cdap) rl_delete(cdap, RL_MT_CDAP); }
    int serialize(char *buf, unsigned int size) const override;
};

struct AddrAllocRequest : public UipcpObject {
    rlm_addr_t requestor;
    rlm_addr_t address;
    bool pending; /* not serialized */

    AddrAllocRequest() : requestor (0), address(RL_ADDR_NULL),
                         pending(true) { }
    AddrAllocRequest(rlm_addr_t a, rlm_addr_t r) : requestor(r), address(a),
                                                 pending(true) { }
    AddrAllocRequest(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};

struct AddrAllocEntries : public UipcpObject {
    std::list<AddrAllocRequest> entries;

    AddrAllocEntries() = default;
    AddrAllocEntries(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const override;
};
#endif  /* __UIPCP_CODECS_H__ */
