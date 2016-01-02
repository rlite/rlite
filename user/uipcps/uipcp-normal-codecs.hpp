#ifndef __UIPCP_CODECS_H__
#define __UIPCP_CODECS_H__

#include <stdint.h>
#include <list>
#include <string>

#include "rlite/common.h"
#include "rlite/cdap.hpp"


struct UipcpObject {
    virtual int serialize(char *buf, unsigned int size) const = 0;
    virtual ~UipcpObject() { }
};

struct EnrollmentInfo : public UipcpObject {
    rl_addr_t address;
    std::list< std::string > lower_difs;
    bool start_early;

    EnrollmentInfo() : address(0), start_early(false) { }
    EnrollmentInfo(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct RinaName {
    std::string apn;
    std::string api;
    std::string aen;
    std::string aei;

    RinaName() { }
    RinaName(const std::string& apn_,
             const std::string& api_,
             const std::string& aen_,
             const std::string& aei_);
    RinaName(const struct rina_name *name);
    operator std::string() const;
    bool operator==(const RinaName& other) const;
    bool operator!=(const RinaName& other) const;
    int rina_name_fill(struct rina_name *name);
};

struct DFTEntry : public UipcpObject {
    RinaName appl_name;
    rl_addr_t address;
    uint64_t timestamp;
    /* Not externally visible (not serialized), true
     * if this entry refers to an application registered
     * locally. */
    bool local;

    DFTEntry() : address(0), timestamp(0), local(false) { }
    DFTEntry(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct DFTSlice : public UipcpObject {
    std::list<DFTEntry> entries;

    DFTSlice() { }
    DFTSlice(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct NeighborCandidate : public UipcpObject {
    std::string apn;
    std::string api;
    rl_addr_t address;
    std::list<std::string> lower_difs;

    NeighborCandidate() { }
    NeighborCandidate(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct NeighborCandidateList : public UipcpObject {
    std::list<NeighborCandidate> candidates;

    NeighborCandidateList() { }
    NeighborCandidateList(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct LowerFlow : public UipcpObject {
    rl_addr_t local_addr;
    rl_addr_t remote_addr;
    unsigned int cost;
    unsigned int seqnum;
    bool state;
    unsigned int age;

    LowerFlow() { }
    LowerFlow(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;

    operator std::string() const;
};

struct LowerFlowList : public UipcpObject {
    std::list<LowerFlow> flows;

    LowerFlowList() { }
    LowerFlowList(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct Property : public UipcpObject {
    std::string name;
    std::string value;

    Property() { }
    Property(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct QosSpec : public UipcpObject {
    std::string name;
    uint32_t qos_id;
    uint64_t avg_bw;
    uint64_t avg_sdu_bw;
    uint64_t peak_bw_duration;
    uint64_t peak_sdu_bw_duration;
    double undetected_bit_error_rate;
    bool partial_delivery;
    bool in_order_delivery;
    int32_t max_sdu_gap;
    uint32_t delay;
    uint32_t jitter;
    std::list<Property> extra_parameters;

    QosSpec() { }
    QosSpec(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct PolicyDescr : public UipcpObject {
    std::string name;
    std::string impl_name;
    std::string version;
    std::list<Property> parameters;

    PolicyDescr() { }
    PolicyDescr(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct WindowBasedFlowCtrlConfig : public UipcpObject {
    uint64_t max_cwq_len; /* closed window queue */
    uint64_t initial_credit;
    PolicyDescr rcvr_flow_ctrl;
    PolicyDescr tx_ctrl;

    WindowBasedFlowCtrlConfig() { }
    WindowBasedFlowCtrlConfig(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct RateBasedFlowCtrlConfig : public UipcpObject {
    uint64_t sending_rate;
    uint64_t time_period; /* us */
    PolicyDescr no_rate_slow_down;
    PolicyDescr no_override_default_peak;
    PolicyDescr rate_reduction;

    RateBasedFlowCtrlConfig() { }
    RateBasedFlowCtrlConfig(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
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

    FlowCtrlConfig() { }
    FlowCtrlConfig(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
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

    RtxCtrlConfig() { }
    RtxCtrlConfig(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct DtcpConfig : public UipcpObject {
    bool flow_ctrl;
    FlowCtrlConfig flow_ctrl_cfg;
    bool rtx_ctrl;
    RtxCtrlConfig rtx_ctrl_cfg;
    PolicyDescr lost_ctrl_pdu;
    PolicyDescr rtt_estimator;

    DtcpConfig() { }
    DtcpConfig(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct ConnPolicies : public UipcpObject {
    bool dtcp_present;
    DtcpConfig dtcp_cfg;
    uint64_t seq_num_rollover_th;
    uint32_t initial_a_timer;
    PolicyDescr rcvr_timer_inact;
    PolicyDescr sender_timer_inact;
    PolicyDescr init_seq_num;

    ConnPolicies() { }
    ConnPolicies(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct ConnId : public UipcpObject {
    uint32_t qos_id;
    uint32_t src_cep;
    uint32_t dst_cep;

    ConnId() { }
    ConnId(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct FlowRequest : public UipcpObject {
    RinaName src_app;
    RinaName dst_app;
    uint64_t src_port;
    uint64_t dst_port;
    rl_addr_t src_addr;
    rl_addr_t dst_addr;
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
    struct rlite_flow_config flowcfg;
    bool initiator;  /* Was me the initiator? */
    /* End of local storage. */

    FlowRequest() : access_ctrl(NULL) { }
    FlowRequest(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct AData : public UipcpObject {
    rl_addr_t src_addr;
    rl_addr_t dst_addr;
    CDAPMessage *cdap;

    AData() : cdap(NULL) { }
    AData(const char *buf, unsigned int size);
    ~AData() { if (cdap) delete cdap; }
    int serialize(char *buf, unsigned int size) const;
};

#endif  /* __UIPCP_CODECS_H__ */
