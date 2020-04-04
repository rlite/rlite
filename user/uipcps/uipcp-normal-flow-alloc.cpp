/*
 * Flow allocation support for normal uipcps.
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

#include <sstream>
#include <iomanip>

#include "uipcp-normal.hpp"
#include "uipcp-normal-ceft.hpp"
#include "uipcp-normal-lower-flows.hpp"
#include "BwRes.pb.h"

using namespace std;

namespace rlite {

struct FlowRequest {
    FlowRequest() = default;
    RL_NONCOPIABLE(FlowRequest);
    gpb::FlowRequest gpb;
    /* Local storage. */
    int invoke_id = 0;
    uint32_t uid  = 0;
    struct rl_flow_config flowcfg;
#define RL_FLOWREQ_INITIATOR 0x1 /* Was I the initiator? */
#define RL_FLOWREQ_SEND_DEL 0x2  /* Should I send a delete message ? */
    uint8_t flags = 0;
    /* End of local storage. */
};

int
UipcpRib::fa_req(struct rl_kmsg_fa_req *req)
{
    std::string remote_node;
    std::string appl_name;
    int ret;

    if (!req->remote_appl) {
        UPE(uipcp, "Null remote application name\n");
        return -1;
    }

    appl_name = string(req->remote_appl);

    /* Lookup the DFT. */
    ret = dft->lookup_req(appl_name, &remote_node,
                          /* no preference */ string(), req->cookie);
    if (ret) {
        /* Return a negative flow allocation response immediately. */
        UPI(uipcp, "No DFT matching entry for destination %s\n",
            req->remote_appl);
        stats.fa_name_lookup_failed++;

        return uipcp_issue_fa_resp_arrived(uipcp, req->local_port,
                                           /*remote_port=*/0, /*remote_cep=*/0,
                                           /*qos_id=*/0, /*remote_addr=*/0,
                                           /*response=*/1, /*cfg=*/nullptr);
    }

    if (!remote_node.empty()) {
        /* DFT lookup request was served immediately, we can go ahead. */
        return fa->fa_req(req, remote_node);
    }

    /* We need to wait for the DFT lookup to complete before we can go
     * ahead. Store the FA request in a list of pending request. */

    /* Make a copy of the request, with some move semantic. */
    std::unique_ptr<struct rl_kmsg_fa_req> reqcopy =
        utils::make_unique<struct rl_kmsg_fa_req>();
    *reqcopy         = *req;
    req->local_appl  = nullptr;
    req->remote_appl = nullptr;
    req->dif_name    = nullptr;
    pending_fa_reqs[appl_name].push_back(std::move(reqcopy));

    return 0;
}

void
UipcpRib::dft_lookup_resolved(const std::string &appl_name,
                              const std::string &remote_node)
{
    auto mit = pending_fa_reqs.find(appl_name);

    if (mit == pending_fa_reqs.end()) {
        UPV(uipcp, "DFT lookup for '%s' resolved, but no pending requests\n",
            appl_name.c_str());
        return;
    }

    /* Go ahead with all the flow allocation requests that were pending
     * waiting for the DFT to resolve this name. */
    if (remote_node.empty()) {
        UPI(uipcp, "No DFT matching entry for destination %s\n",
            appl_name.c_str());
        stats.fa_name_lookup_failed++;
    }
    for (auto &fr : mit->second) {
        if (remote_node.empty()) {
            /* Return a negative flow allocation response. */
            uipcp_issue_fa_resp_arrived(uipcp, fr->local_port,
                                        /*remote_port=*/0, /*remote_cep=*/0,
                                        /*qos_id=*/0, /*remote_addr=*/0,
                                        /*response=*/1, /*cfg=*/nullptr);
        } else {
            fa->fa_req(fr.get(), remote_node);
        }
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(fr.get()));
    }
    pending_fa_reqs.erase(mit);
}

class LocalFlowAllocator : public FlowAllocator {
public:
    RL_NODEFAULT_NONCOPIABLE(LocalFlowAllocator);
    LocalFlowAllocator(UipcpRib *_ur) : FlowAllocator(_ur) {}
    ~LocalFlowAllocator() {}

    void dump(std::stringstream &ss) const override;
    void dump_memtrack(std::stringstream &ss) const override;

    std::unordered_map<rl_port_t, std::unique_ptr<FlowRequest>> flow_reqs;
    std::unordered_map<unsigned int, std::unique_ptr<FlowRequest>> flow_reqs_in;
    std::unordered_map</*invoke_id=*/int, std::unique_ptr<FlowRequest>>
        flow_reqs_out;

    int fa_req(struct rl_kmsg_fa_req *req,
               const std::string &remote_node) override;
    int fa_resp(struct rl_kmsg_fa_resp *resp) override;

    int flow_deallocated(struct rl_kmsg_flow_deallocated *req) override;

    int flows_handler_create(const CDAPMessage *rm,
                             const MsgSrcInfo &src) override;
    int flows_handler_create_r(const CDAPMessage *rm) override;
    int flows_handler_create_r(const CDAPMessage *rm, int invoke_id);
    int flows_handler_delete(const CDAPMessage *rm,
                             const MsgSrcInfo &src) override;

    /* Default value for the A timer in milliseconds. */
    static constexpr int kATimerMsecsDflt = 20;

    /* Default value for the R timer in milliseconds. */
    static constexpr int kRtxTimerMsecsDflt = 1000;

    /* Default value for the maximum length of the retransmission queue
     * (in PDUs). */
    static constexpr int kRtxQueueMaxLen = 512;

    /* Default value for the flow control initial credit (windows size in terms
       of PDUs). */
    static constexpr int kFlowControlInitialCredit = 512;

    /* Default value for the maximum length of the flow control closed window
     * queue (in terms of PDUs). */
    static constexpr int kFlowControlMaxCwqLen = 128;

protected:
    void flowspec2flowcfg(const struct rina_flow_spec *spec,
                          struct rl_flow_config *cfg,
                          rlm_qosid_t *qos_id) const;
    void policies2flowcfg(struct rl_flow_config *cfg, const FlowRequest *freq);
};

/* Translate a local flow configuration into the standard
 * representation to be used in the FlowRequest CDAP
 * message. */
static void
flowcfg2policies(const struct rl_flow_config *cfg, FlowRequest *freq)
{
    auto qos           = new gpb::QosSpec();
    auto policies      = new gpb::ConnPolicies();
    auto dtcp_cfg      = new gpb::DtcpConfig();
    auto flow_ctrl_cfg = new gpb::FlowCtrlConfig();
    auto rtx_ctrl_cfg  = new gpb::RtxCtrlConfig();

    freq->gpb.set_allocated_qos(qos);
    freq->gpb.set_allocated_policies(policies);

    qos->set_partial_delivery(!cfg->msg_boundaries);
    qos->set_in_order_delivery(cfg->in_order_delivery);
    qos->set_max_sdu_gap(cfg->max_sdu_gap);
    qos->set_avg_bw(cfg->dtcp.bandwidth);

    policies->set_dtcp_present(DTCP_PRESENT(cfg->dtcp));
    policies->set_initial_a_timer(cfg->dtcp.initial_a); /* name mismatch... */
    /* missing seq_num_rollover_th */

    policies->set_allocated_dtcp_cfg(dtcp_cfg);
    dtcp_cfg->set_flow_ctrl(cfg->dtcp.flags & DTCP_CFG_FLOW_CTRL);
    dtcp_cfg->set_rtx_ctrl(cfg->dtcp.flags & DTCP_CFG_RTX_CTRL);

    dtcp_cfg->set_allocated_flow_ctrl_cfg(flow_ctrl_cfg);
    flow_ctrl_cfg->set_window_based(cfg->dtcp.fc.fc_type == RLITE_FC_T_WIN);
    flow_ctrl_cfg->set_rate_based(cfg->dtcp.fc.fc_type == RLITE_FC_T_RATE);
    if (cfg->dtcp.fc.fc_type == RLITE_FC_T_WIN) {
        auto win = new gpb::WindowBasedFlowCtrlConfig();

        flow_ctrl_cfg->set_allocated_window_based_config(win);
        win->set_max_cwq_len(cfg->dtcp.fc.cfg.w.max_cwq_len);
        win->set_initial_credit(cfg->dtcp.fc.cfg.w.initial_credit);

    } else if (cfg->dtcp.fc.fc_type == RLITE_FC_T_RATE) {
        auto rtx = new gpb::RateBasedFlowCtrlConfig();

        flow_ctrl_cfg->set_allocated_rate_based_config(rtx);
        rtx->set_sender_rate(cfg->dtcp.fc.cfg.r.sender_rate);
        rtx->set_time_period(cfg->dtcp.fc.cfg.r.time_period);
    }

    dtcp_cfg->set_allocated_rtx_ctrl_cfg(rtx_ctrl_cfg);
    rtx_ctrl_cfg->set_max_time_to_retry(cfg->dtcp.rtx.max_time_to_retry);
    rtx_ctrl_cfg->set_data_rxmsn_max(
        cfg->dtcp.rtx.data_rxms_max); /* name mismatch... */
    rtx_ctrl_cfg->set_initial_rtx_timeout(cfg->dtcp.rtx.initial_rtx_timeout);
}

/* Translate a standard flow policies specification from FlowRequest
 * CDAP message into a local flow configuration. */
void
LocalFlowAllocator::policies2flowcfg(struct rl_flow_config *cfg,
                                     const FlowRequest *freq)
{
    const gpb::QosSpec &qos    = freq->gpb.qos();
    const gpb::ConnPolicies &p = freq->gpb.policies();

    cfg->msg_boundaries    = !qos.partial_delivery();
    cfg->in_order_delivery = qos.in_order_delivery();
    cfg->max_sdu_gap       = qos.max_sdu_gap();
    cfg->dtcp.bandwidth    = qos.avg_bw();
    cfg->dtcp.initial_a    = p.initial_a_timer();

    cfg->dtcp.flags = 0;
    if (p.dtcp_cfg().flow_ctrl()) {
        cfg->dtcp.flags |= DTCP_CFG_FLOW_CTRL;
    }
    if (p.dtcp_cfg().rtx_ctrl()) {
        cfg->dtcp.flags |= DTCP_CFG_RTX_CTRL;
    }

    cfg->dtcp.fc.fc_type = RLITE_FC_T_NONE;
    if (p.dtcp_cfg().flow_ctrl_cfg().window_based()) {
        cfg->dtcp.fc.fc_type = RLITE_FC_T_WIN;
        cfg->dtcp.fc.cfg.w.max_cwq_len =
            p.dtcp_cfg().flow_ctrl_cfg().window_based_config().max_cwq_len();
        cfg->dtcp.fc.cfg.w.initial_credit =
            p.dtcp_cfg().flow_ctrl_cfg().window_based_config().initial_credit();

    } else if (p.dtcp_cfg().flow_ctrl_cfg().rate_based()) {
        cfg->dtcp.fc.fc_type = RLITE_FC_T_RATE;
        cfg->dtcp.fc.cfg.r.sender_rate =
            p.dtcp_cfg().flow_ctrl_cfg().rate_based_config().sender_rate();
        cfg->dtcp.fc.cfg.r.time_period =
            p.dtcp_cfg().flow_ctrl_cfg().rate_based_config().time_period();
    }

    cfg->dtcp.rtx.max_time_to_retry =
        p.dtcp_cfg().rtx_ctrl_cfg().max_time_to_retry();
    cfg->dtcp.rtx.data_rxms_max = p.dtcp_cfg().rtx_ctrl_cfg().data_rxmsn_max();
    cfg->dtcp.rtx.initial_rtx_timeout =
        p.dtcp_cfg().rtx_ctrl_cfg().initial_rtx_timeout();
    if (p.dtcp_cfg().rtx_ctrl()) {
        cfg->dtcp.rtx.max_rtxq_len =
            rib->get_param_value<int>(FlowAllocator::Prefix, "max-rtxq-len");
    }
}

#ifndef RL_USE_QOS_CUBES
/* Any modification to this function must be also reported in the inverse
 * function flowcfg2flowspec(). */
void
LocalFlowAllocator::flowspec2flowcfg(const struct rina_flow_spec *spec,
                                     struct rl_flow_config *cfg,
                                     rlm_qosid_t *qos_id) const
{
    bool force_flow_control =
        rib->get_param_value<bool>(FlowAllocator::Prefix, "force-flow-control");
    auto initial_a =
        rib->get_param_value<Msecs>(FlowAllocator::Prefix, "initial-a");

    *qos_id = 0; /* default */
    memset(cfg, 0, sizeof(*cfg));

    cfg->max_sdu_gap       = spec->max_sdu_gap;
    cfg->in_order_delivery = spec->in_order_delivery;
    cfg->msg_boundaries    = spec->msg_boundaries;
    cfg->dtcp.bandwidth    = spec->avg_bandwidth;

    if (spec->max_sdu_gap == 0) {
        /* We need retransmission control. */
        cfg->dtcp.flags |= DTCP_CFG_RTX_CTRL;
        cfg->in_order_delivery          = 1;
        cfg->dtcp.rtx.max_time_to_retry = 15; /* unused for now */
        cfg->dtcp.rtx.data_rxms_max     = RL_DATA_RXMS_MAX_DFLT;
        cfg->dtcp.rtx.initial_rtx_timeout =
            rib->get_param_value<Msecs>(FlowAllocator::Prefix,
                                        "initial-rtx-timeout")
                .count();
        cfg->dtcp.rtx.max_rtxq_len =
            rib->get_param_value<int>(FlowAllocator::Prefix, "max-rtxq-len");
        cfg->dtcp.initial_a = initial_a.count();
    }

    /* Delay, loss and jitter ignored for now. */
    (void)spec->max_delay;
    (void)spec->max_loss;
    (void)spec->max_jitter;

    if (force_flow_control || spec->max_sdu_gap == 0) {
        /* We enable flow control if forced by policy or if also
         * retransmission control is needed. */
        cfg->dtcp.flags |= DTCP_CFG_FLOW_CTRL;
        cfg->dtcp.fc.cfg.w.max_cwq_len =
            rib->get_param_value<int>(FlowAllocator::Prefix, "max-cwq-len");
        cfg->dtcp.fc.cfg.w.initial_credit =
            rib->get_param_value<int>(FlowAllocator::Prefix, "initial-credit");
        cfg->dtcp.fc.fc_type = RLITE_FC_T_WIN;
        cfg->dtcp.initial_a  = initial_a.count();
    }

    if (spec->avg_bandwidth) {
        cfg->dtcp.flags |= DTCP_CFG_SHAPER;
    }
}
#endif /* !RL_USE_QOS_CUBES */

/* (1) Initiator FA <-- Initiator application : FA_REQ */
int
LocalFlowAllocator::fa_req(struct rl_kmsg_fa_req *req,
                           const std::string &remote_node)
{
    auto freq        = utils::make_unique<FlowRequest>();
    string dest_appl = string(req->remote_appl);
    std::unique_ptr<CDAPMessage> m;
    struct rl_flow_config flowcfg;
    rlm_qosid_t qos_id = 0; /* default */
    gpb::ConnId *conn_id;
    int ret;

    if (req->flowspec.version != RINA_FLOW_SPEC_VERSION) {
        UPE(rib->uipcp,
            "Version mismatch in flow spec (got %u, "
            "expected %u)\n",
            req->flowspec.version, RINA_FLOW_SPEC_VERSION);
        return -1;
    }

#ifndef RL_USE_QOS_CUBES
    /* Translate the flow specification into a local flow configuration
     * and the corresponding QoS id. */
    flowspec2flowcfg(&req->flowspec, &flowcfg, &qos_id);
#else  /* RL_USE_QOS_CUBES */
    map<string, struct rl_flow_config>::iterator qcmi;
    string cubename;

    /* Translate the flow specification into a local flow configuration.
     * For now this is accomplished by just specifying the
     * QoSCube name in the flow specification. */
    cubename = string(req->flowspec.cubename);
    qcmi     = qos_cubes.find(cubename);
    if (qcmi == qos_cubes.end()) {
        UPI(uipcp,
            "Cannot find QoSCube '%s': Using default flow configuration\n",
            cubename.c_str());
        rl_flow_cfg_default(&flowcfg);
    } else {
        flowcfg = qcmi->second;
        UPI(uipcp, "QoSCube '%s' selected\n", qcmi->first.c_str());
    }
#endif /* RL_USE_QOS_CUBES */

    flowcfg2policies(&flowcfg, freq.get());

    freq->gpb.set_allocated_src_app(
        apname2gpb(req->local_appl)); /* req->local_appl may be nullptr */
    freq->gpb.set_allocated_dst_app(apname2gpb(dest_appl));
    freq->gpb.set_src_port(req->local_port);
    freq->gpb.set_dst_port(0);
    freq->gpb.set_src_ipcp(rib->myname);
    freq->gpb.set_dst_ipcp(remote_node);
    conn_id = freq->gpb.add_connections();
    conn_id->set_qosid(qos_id);
    conn_id->set_src_cep(req->local_cep);
    conn_id->set_dst_cep(0);
    freq->gpb.set_cur_conn_idx(0);
    freq->gpb.set_state(true);
    freq->uid = req->uid; /* on initiator side, uid is generated by
                           * the kernel, we just store it */
    freq->flowcfg = flowcfg;
    freq->gpb.set_max_create_flow_retries(3);
    freq->gpb.set_create_flow_retries(0);
    freq->gpb.set_hop_cnt(0);

    m = utils::make_unique<CDAPMessage>();
    m->m_create(FlowObjClass, TableName);

    m->invoke_id = freq->invoke_id = rib->invoke_id_mgr.get_invoke_id();
    freq->flags                    = RL_FLOWREQ_INITIATOR | RL_FLOWREQ_SEND_DEL;

    ret = rib->send_to_dst_node(std::move(m), remote_node, &freq.get()->gpb);
    if (ret) {
        return ret;
    }
    flow_reqs_out[freq->invoke_id] = std::move(freq);
    rib->stats.fa_request_issued++;

    return 0;
}

/* (4) Initiator FA <-- Slave FA : M_CREATE_R */
int
LocalFlowAllocator::flows_handler_create_r(const CDAPMessage *rm)
{
    return flows_handler_create_r(rm, rm->invoke_id);
}

int
LocalFlowAllocator::flows_handler_create_r(const CDAPMessage *rm, int invoke_id)
{
    rlm_addr_t remote_addr;
    const char *objbuf;
    size_t objlen;

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(rib->uipcp, "M_CREATE_R does not contain a nested message\n");
        return 0;
    }

    auto f = flow_reqs_out.find(invoke_id);
    if (f == flow_reqs_out.end()) {
        UPE(rib->uipcp,
            "M_CREATE_R does not match any pending request (invoke_id=%d)\n",
            invoke_id);
        return 0;
    }

    /* Move the FlowRequest object to the final data structure (flow_reqs). */
    FlowRequest remote_freq;
    FlowRequest *freq               = f->second.get();
    flow_reqs[freq->gpb.src_port()] = std::move(f->second);
    flow_reqs_out.erase(f);

    remote_freq.gpb.ParseFromArray(objbuf, objlen);
    /* Update the local freq object with the remote one. */
    freq->gpb.set_dst_port(remote_freq.gpb.dst_port());
    freq->gpb.mutable_connections(0)->set_dst_cep(
        remote_freq.gpb.connections(0).dst_cep());

    rib->stats.fa_response_received++;

    remote_addr = rib->lookup_node_address(freq->gpb.dst_ipcp());
    if (remote_addr == RL_ADDR_NULL) {
        UPE(rib->uipcp, "Could not find address of remote IPCP %s\n",
            freq->gpb.dst_ipcp().c_str());
        return 0;
    }

    return uipcp_issue_fa_resp_arrived(
        rib->uipcp, freq->gpb.src_port(), freq->gpb.dst_port(),
        freq->gpb.connections(0).dst_cep(), freq->gpb.connections(0).qosid(),
        remote_addr, rm->result ? 1 : 0, &freq->flowcfg);
}

/* (2) Slave FA <-- Initiator FA : M_CREATE */
int
LocalFlowAllocator::flows_handler_create(const CDAPMessage *rm,
                                         const MsgSrcInfo &src)
{
    rlm_addr_t remote_addr;
    const char *objbuf;
    size_t objlen;

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(rib->uipcp, "M_CREATE does not contain a nested message\n");
        return 0;
    }

    auto freq = utils::make_unique<FlowRequest>();
    std::string local_appl, remote_appl;
    struct rl_flow_config flowcfg;

    freq->gpb.ParseFromArray(objbuf, objlen);
    remote_addr = rib->lookup_node_address(freq->gpb.src_ipcp());
    if (freq->gpb.connections_size() < 1 || remote_addr != src.addr) {
        /* In future we may allow remote_addr != src.addr, which
         * happens in case of intermediated flow allocation. */
        std::unique_ptr<CDAPMessage> m;
        std::stringstream error_msg;

        if (freq->gpb.connections_size() < 1) {
            error_msg << "No connections specified on this flow";
        } else if (remote_addr != src.addr) {
            error_msg << "Flow allocation from unknown neighbor '%s'"
                      << freq->gpb.src_ipcp();
        }

        UPE(rib->uipcp, "%s\n", error_msg.str().c_str());
        m = utils::make_unique<CDAPMessage>();
        m->m_create_r(rm->obj_class, rm->obj_name, 0, -1, error_msg.str());
        m->invoke_id = rm->invoke_id;

        return rib->send_to_dst_addr(std::move(m), remote_addr);
    }

    /* freq->gpb.dst_app() is registered with us, let's go ahead. */

    local_appl  = apname2string(freq->gpb.dst_app());
    remote_appl = apname2string(freq->gpb.src_app());
    policies2flowcfg(&flowcfg, freq.get());

    freq->invoke_id = rm->invoke_id;
    freq->flags     = RL_FLOWREQ_SEND_DEL;
    freq->uid = kevent_id_cnt++; /* on slave side uid is generated by us, and
                                  * it is also used as 'event_id' by the
                                  * kernel */

    uipcp_issue_fa_req_arrived(
        rib->uipcp, freq->uid, freq->gpb.src_port(),
        freq->gpb.connections(0).src_cep(), freq->gpb.connections(0).qosid(),
        remote_addr, local_appl.c_str(), remote_appl.c_str(), &flowcfg);
    flow_reqs_in[freq->uid] = std::move(freq);
    rib->stats.fa_request_received++;

    return 0;
}

/* (3) Slave FA <-- Slave application : FA_RESP */
int
LocalFlowAllocator::fa_resp(struct rl_kmsg_fa_resp *resp)
{
    std::unique_ptr<CDAPMessage> m;
    string reason;
    int ret;

    /* Lookup the corresponding FlowRequest. */

    auto f = flow_reqs_in.find(resp->kevent_id);
    if (f == flow_reqs_in.end()) {
        UPE(rib->uipcp,
            "Spurious flow allocation response, no request for kevent_id %u\n",
            resp->kevent_id);
        return -1;
    }

    FlowRequest *freq = f->second.get();

    /* Update the freq object with the port-id and cep-id allocated by
     * the kernel. */
    freq->gpb.set_dst_port(resp->port_id);
    freq->gpb.mutable_connections(0)->set_dst_cep(resp->cep_id);

    if (resp->response) {
        reason = "Application refused the accept the flow request";
    } else {
        /* Move the freq object from the temporary map to the right one. */
        flow_reqs[resp->port_id] = std::move(f->second);
    }

    m = utils::make_unique<CDAPMessage>();
    m->m_create_r(FlowObjClass, TableName, 0, resp->response ? -1 : 0, reason);
    m->invoke_id = freq->invoke_id;

    ret = rib->send_to_dst_node(std::move(m), freq->gpb.src_ipcp(), &freq->gpb);
    flow_reqs_in.erase(f); /* freq cannot be used after this instruction */
    rib->stats.fa_response_issued++;

    return ret;
}

int
LocalFlowAllocator::flow_deallocated(struct rl_kmsg_flow_deallocated *req)
{
    std::unique_ptr<CDAPMessage> m;
    std::stringstream remote_obj_name;
    std::string remote_node;
    bool send_del;

    /* Lookup the corresponding FlowRequest by port_id. */
    auto f = flow_reqs.find(req->local_port_id);
    if (f == flow_reqs.end()) {
        UPE(rib->uipcp,
            "Spurious flow deallocated notification, no object with port_id "
            "%u\n",
            req->local_port_id);
        return -1;
    }

    std::unique_ptr<FlowRequest> freq = std::move(f->second);

    flow_reqs.erase(f);
    send_del = (freq->flags & RL_FLOWREQ_SEND_DEL);

    UPV(rib->uipcp, "Removed flow request with port_id %u\n",
        req->local_port_id);

    if (!send_del) {
        return 0;
    }

    /* We should wait 2 MPL here before notifying the peer. */
    m = utils::make_unique<CDAPMessage>();
    remote_obj_name << TableName << "/";
    if (freq->flags & RL_FLOWREQ_INITIATOR) {
        remote_obj_name << freq->gpb.dst_port();
        remote_node = freq->gpb.dst_ipcp();
    } else {
        remote_obj_name << freq->gpb.src_port();
        remote_node = freq->gpb.src_ipcp();
    }
    m->m_delete(FlowObjClass, remote_obj_name.str());

    return rib->send_to_dst_node(std::move(m), remote_node);
}

int
LocalFlowAllocator::flows_handler_delete(const CDAPMessage *rm,
                                         const MsgSrcInfo &src)
{
#if 0
    rlm_addr_t expected_src_addr;
#endif
    rl_port_t local_port;
    stringstream decode;
    string objname;

    decode << rm->obj_name.substr(TableName.size() + 1);
    decode >> local_port;

    /* Lookup the corresponding FlowRequest by port_id. */
    auto f = flow_reqs.find(local_port);
    if (f == flow_reqs.end()) {
        UPV(rib->uipcp, "No flow port_id %u (may be already deleted locally)\n",
            local_port);
        return 0;
    }

    FlowRequest *freq = f->second.get();

#if 0
    expected_src_addr = rib->lookup_node_address(
        (freq->flags & RL_FLOWREQ_INITIATOR) ? freq->gpb.dst_ipcp()
                                             : freq->gpb.src_ipcp());
    if (src.addr != expected_src_addr) {
        UPW(rib->uipcp,
            "Remote flow deallocation from unmatching address "
            "'%lu' (expected=%lu)\n",
            (long unsigned)src.addr, (long unsigned)expected_src_addr);
        return 0;
    }
#endif

    /* We received a delete request from the peer, so we won't need to send
     * him a delete request. */
    freq->flags &= ~RL_FLOWREQ_SEND_DEL;

    return uipcp_issue_flow_dealloc(rib->uipcp, local_port, freq->uid);
}

int
FlowAllocator::rib_handler(const CDAPMessage *rm, const MsgSrcInfo &src)
{
    switch (rm->op_code) {
    case gpb::M_CREATE:
        return flows_handler_create(rm, src);

    case gpb::M_CREATE_R:
        return flows_handler_create_r(rm);

    case gpb::M_DELETE:
        return flows_handler_delete(rm, src);

    case gpb::M_DELETE_R:
        UPE(rib->uipcp, "M_DELETE_R(flowalloc) not supported\n");
        break;

    default:
        UPE(rib->uipcp,
            "M_CREATE, M_CREATE_R, M_DELETE or M_DELETE_R expected\n");
        break;
    }

    return 0;
}

void
LocalFlowAllocator::dump(std::stringstream &ss) const
{
    ss << "Supported flows (Src/Dst <Appl,IPCP,port>):" << endl;
    for (const auto &kvf : flow_reqs) {
        const auto &freq = kvf.second;

        ss << "    [" << ((freq->flags & RL_FLOWREQ_INITIATOR) ? "L" : "R")
           << "]"
           << ", Src=<" << apname2string(freq->gpb.src_app()) << ","
           << freq->gpb.src_ipcp() << "," << freq->gpb.src_port() << "> Dst=<"
           << apname2string(freq->gpb.dst_app()) << "," << freq->gpb.dst_ipcp()
           << "," << freq->gpb.dst_port() << "> Connections: [";
        for (int i = 0; i < freq->gpb.connections_size(); i++) {
            ss << "<SrcCep=" << freq->gpb.connections(i).src_cep()
               << ", DstCep=" << freq->gpb.connections(i).dst_cep()
               << ", QosId=" << freq->gpb.connections(i).qosid() << "> ";
        }
        ss << "]" << endl;
    }
    ss << endl;
}

void
LocalFlowAllocator::dump_memtrack(std::stringstream &ss) const
{
    ss << endl << "Temporary tables:" << endl;
    ss << "    " << flow_reqs_in.size() << " + " << flow_reqs_out.size()
       << " elements in the "
          "temporary flow request table"
       << endl;
}

class BwResFlowAllocator : public LocalFlowAllocator {
    class Replica : public CeftReplica {
        struct Command {
            char flow_id[128];
            char from[32];
            char to[31];
            uint8_t opcode;
            uint32_t bw;
            uint64_t src_addr;
            uint64_t dst_addr;
            uint32_t src_cepid;
            uint32_t dst_cepid;
            static constexpr uint8_t OpcodeAdd     = 1;
            static constexpr uint8_t OpcodeReserve = 2;
            static constexpr uint8_t OpcodeFree    = 3;
        } __attribute__((packed));
        static_assert(sizeof(Command) ==
                          sizeof(Command::flow_id) + sizeof(Command::from) +
                              sizeof(Command::to) + sizeof(Command::bw) +
                              sizeof(Command::src_addr) * 2 +
                              sizeof(Command::src_cepid) * 2 +
                              sizeof(Command::opcode),
                      "Invalid memory layout for class Replica::Command");

        struct Entry {
            NodeId from;
            NodeId to;
            std::vector<NodeId> path;
            unsigned int bw;
            rlm_addr_t src_addr;
            rlm_addr_t dst_addr;
            rlm_cepid_t src_cepid;
            rlm_cepid_t dst_cepid;
        };

        std::unordered_map<string, Entry> table;

    public:
        Replica(BwResFlowAllocator *fa, std::list<raft::ReplicaId> peers)
            : CeftReplica(fa->rib, std::string("bwres-fa-") + fa->rib->myname,
                          fa->rib->myname,
                          std::string("/tmp/bwres-fa-") +
                              std::to_string(fa->rib->uipcp->id) +
                              std::string("-") + fa->rib->myname,
                          sizeof(Command), FlowAllocator::TableName){};
        int apply(const char *const serbuf, CDAPMessage *const rm) override;
        virtual int replica_process_rib_msg(
            const CDAPMessage *rm, rlm_addr_t src_addr,
            std::vector<CommandToSubmit> *commands) override;
        void dump(std::stringstream &ss) const;

        std::unordered_map</*invoke_id=*/int, int> pending;
    };

    std::unique_ptr<Replica> raft;

    class Client : public CeftClient {
        struct PendingReq : public CeftClient::PendingReq {
            std::string flow_id;
            PendingReq() = default;
            PendingReq(gpb::OpCode op_code, Msecs timeout,
                       const std::string flow_id)
                : CeftClient::PendingReq(op_code, timeout), flow_id(flow_id)
            {
            }
            std::unique_ptr<CeftClient::PendingReq> clone() const override
            {
                return utils::make_unique<PendingReq>(*this);
            }
        };
        BwResFlowAllocator *fa;

    public:
        Client(BwResFlowAllocator *fa, std::list<raft::ReplicaId> names)
            : CeftClient(fa->rib, std::move(names)), fa(fa)
        {
        }
        int allocate(const FlowRequest &freq);
        int client_process_rib_msg(const CDAPMessage *rm,
                                   CeftClient::PendingReq *const bpr,
                                   rlm_addr_t src_addr) override;
        int free(const FlowRequest &freq);
    };
    std::unique_ptr<Client> client;

    std::unordered_map<rl_port_t, rlm_addr_t> leader_pending;

public:
    RL_NODEFAULT_NONCOPIABLE(BwResFlowAllocator);
    BwResFlowAllocator(UipcpRib *_ur) : LocalFlowAllocator(_ur) {}
    ~BwResFlowAllocator() {}
    int reconfigure() override;
    int fa_req(struct rl_kmsg_fa_req *req,
               const std::string &remote_node) override;
    int rib_handler(const CDAPMessage *rm, const MsgSrcInfo &src) override;
    int flow_deallocated(struct rl_kmsg_flow_deallocated *req) override;
    void dump(std::stringstream &ss) const override;
    int flows_handler_create(const CDAPMessage *rm,
                             const MsgSrcInfo &src) override;
    // int flows_handler_create_r(const CDAPMessage *rm, int invoke_id);
    int flows_handler_delete(const CDAPMessage *rm,
                             const MsgSrcInfo &src) override;
    int fa_resp(struct rl_kmsg_fa_resp *resp) override;

    /* Th default bandwidth for flows that do not set it, bits per second */
    static constexpr int DefaultBandwidth = 5 * 1000 * 100;
};

int
BwResFlowAllocator::reconfigure()
{
    list<raft::ReplicaId> peers;
    string replicas;

    if (client) {
        return 0; /* nothing to do */
    }

    replicas =
        rib->get_param_value<std::string>(FlowAllocator::Prefix, "replicas");
    if (replicas.empty()) {
        UPW(rib->uipcp, "replicas param not configured\n");
        return 0;
    }
    UPD(rib->uipcp, "replicas = %s\n", replicas.c_str());
    peers = utils::strsplit<std::list>(replicas, ',');

    /* Create the client anyway. */
    client = utils::make_unique<Client>(this, peers);
    UPI(rib->uipcp, "Client initialized\n");

    /* I'm one of the replicas. Create a Raft state machine and
     * initialize it. */
    auto it = std::find(peers.begin(), peers.end(), rib->myname);
    if (it != peers.end()) {
        raft = utils::make_unique<Replica>(this, peers);
        peers.erase(it); /* remove myself */

        auto election_timeout = rib->get_param_value<Msecs>(
            FlowAllocator::Prefix, "raft-election-timeout");
        auto heartbeat_timeout = rib->get_param_value<Msecs>(
            FlowAllocator::Prefix, "raft-heartbeat-timeout");
        auto rtx_timeout = rib->get_param_value<Msecs>(FlowAllocator::Prefix,
                                                       "raft-rtx-timeout");
        raft->set_election_timeout(election_timeout, election_timeout * 2);
        raft->set_heartbeat_timeout(heartbeat_timeout);
        raft->set_retransmission_timeout(rtx_timeout);

        return raft->init(peers);
    }

    return 0;
}

int
BwResFlowAllocator::Replica::apply(const char *const serbuf,
                                   CDAPMessage *const rm)
{
    auto c = reinterpret_cast<const Command *const>(serbuf);

    assert(c->opcode == Command::OpcodeAdd ||
           c->opcode == Command::OpcodeReserve ||
           c->opcode == Command::OpcodeFree);
    if (c->opcode == Command::OpcodeAdd) {
        if (table.find(c->flow_id) == table.end()) {
            table[c->flow_id]      = Entry();
            table[c->flow_id].from = c->from;
            table[c->flow_id].to   = c->to;
            table[c->flow_id].path.push_back(c->from);
            table[c->flow_id].path.push_back(c->to);
            table[c->flow_id].bw = c->bw;
        } else {
            table[c->flow_id].to = c->to;
            table[c->flow_id].path.push_back(c->to);
        }
    } else if (c->opcode == Command::OpcodeReserve) {
        BwResRouting *routing = dynamic_cast<BwResRouting *>(rib->routing);
        routing->reserve_flow(table[c->flow_id].path, table[c->flow_id].bw);
        table[c->flow_id].src_addr  = c->src_addr;
        table[c->flow_id].dst_addr  = c->dst_addr;
        table[c->flow_id].src_cepid = c->src_cepid;
        table[c->flow_id].dst_cepid = c->dst_cepid;
        UPD(rib->uipcp, "Commit %s <-- %u\n", c->flow_id, table[c->flow_id].bw);
    } else if (c->opcode == Command::OpcodeFree) {
        BwResRouting *routing = dynamic_cast<BwResRouting *>(rib->routing);
        routing->free_flow(table[c->flow_id].path, table[c->flow_id].bw);
        UPD(rib->uipcp, "Commit %s <-- -%u\n", c->flow_id,
            table[c->flow_id].bw);
        table.erase(c->flow_id);
    }

    return 0;
}

int
BwResFlowAllocator::Replica::replica_process_rib_msg(
    const CDAPMessage *rm, rlm_addr_t src_addr,
    std::vector<CommandToSubmit> *commands)
{
    struct uipcp *uipcp = rib->uipcp;

    if (rm->obj_class != ObjClass) {
        UPE(uipcp, "Unexpected object class '%s'\n", rm->obj_class.c_str());
        return 0;
    }

    /* We are the leader (so we can go ahead and serve the request). */
    if (!leader()) {
        /* We are not the leader. We * need to deny the request to preserve
         * consistency. */
        UPD(uipcp, "Ignoring request, let the leader answer\n");
        return 0;
    }

    if (rm->op_code == gpb::M_CREATE) {
        /* We received an M_CREATE sent by Client::allocate() and we are the
         * leader. */
        auto m = utils::make_unique<CDAPMessage>();

        m->op_code   = gpb::M_CREATE;
        m->obj_name  = rm->obj_name;
        m->obj_class = FlowAllocator::FlowObjClass;
        m->invoke_id = rm->invoke_id;

        int invoke_id = stoi(rm->obj_name.substr(rm->obj_name.rfind("/") + 1));

        gpb::FlowRequest freq;
        const char *objbuf;
        size_t objlen;
        rm->get_obj_value(objbuf, objlen);
        freq.ParseFromArray(objbuf, objlen);

        m->set_obj_value(objbuf, objlen);

        std::string flow_id(freq.src_ipcp() + freq.dst_ipcp() +
                            std::to_string(freq.src_port()));
        pending[rm->invoke_id] = invoke_id;

        rib->send_to_dst_node(std::move(m), freq.dst_ipcp());
    } else if (rm->op_code == gpb::M_CREATE_R) {
        auto m = utils::make_unique<CDAPMessage>();

        int invoke_id = pending[rm->invoke_id];

        m->op_code   = gpb::M_CREATE_R;
        m->obj_name  = rm->obj_name + "/" + to_string(invoke_id);
        m->obj_class = FlowObjClass;
        m->invoke_id = rm->invoke_id;

        gpb::FlowRequest freq;
        const char *objbuf;
        size_t objlen;
        rm->get_obj_value(objbuf, objlen);
        freq.ParseFromArray(objbuf, objlen);

        std::string from(freq.src_ipcp());
        std::string to(freq.dst_ipcp());
        int bw = freq.qos().avg_bw();

        std::string flow_id(from + to + std::to_string(freq.src_port()));

        if (rm->result) {
            m->result        = rm->result;
            m->result_reason = rm->result_reason;
            rib->send_to_dst_node(std::move(m), freq.src_ipcp());
            return 0;
        }

        BwResRouting *routing    = dynamic_cast<BwResRouting *>(rib->routing);
        std::vector<NodeId> path = routing->find_flow_path(from, to, bw);

        if (path.empty()) {
            m->result        = -1;
            m->result_reason = "No suitable path found";
            UPD(rib->uipcp, "No path found\n");
            rib->send_to_dst_node(std::move(m), freq.src_ipcp());
            return 0;
        }

        UPD(rib->uipcp, "Found a suitable path\n");

        rlm_addr_t src_addr   = rib->lookup_node_address(freq.src_ipcp());
        rlm_addr_t dst_addr   = rib->lookup_node_address(freq.dst_ipcp());
        rlm_cepid_t src_cepid = freq.connections(0).src_cep();
        rlm_cepid_t dst_cepid = freq.connections(0).dst_cep();

        for (auto src = path.begin(); std::next(src) != path.end(); ++src) {
            auto dst = std::next(src);

            auto cbuf  = std::unique_ptr<char[]>(new char[sizeof(Command)]);
            Command *c = reinterpret_cast<Command *>(cbuf.get());
            memset(c, 0, sizeof(*c));

            /* Fill in the command struct (already serialized). */
            strncpy(c->flow_id, flow_id.c_str(), sizeof(c->flow_id) - 1);
            strncpy(c->from, src->c_str(), sizeof(c->from) - 1);
            strncpy(c->to, dst->c_str(), sizeof(c->to) - 1);
            c->bw     = bw;
            c->opcode = Command::OpcodeAdd;

            /* Return the command to the caller. */
            commands->push_back(make_pair(std::move(cbuf), nullptr));

            if (!(src == path.begin() && std::next(dst) == path.end())) {
                auto m_src       = utils::make_unique<CDAPMessage>();
                m_src->op_code   = gpb::M_CREATE;
                m_src->obj_name  = Routing::TableName;
                m_src->obj_class = BwResRouting::PerFlowObjClass;

                auto m_dst       = utils::make_unique<CDAPMessage>();
                m_dst->op_code   = gpb::M_CREATE;
                m_dst->obj_name  = Routing::TableName;
                m_dst->obj_class = BwResRouting::PerFlowObjClass;

                gpb::BwResRoute route_src;
                gpb::BwResRoute route_dst;

                route_src.set_src_addr(src_addr);
                route_src.set_dst_addr(dst_addr);
                route_src.set_src_cepid(src_cepid);
                route_src.set_dst_cepid(dst_cepid);
                route_src.set_next_hop(*dst);

                route_dst.set_src_addr(dst_addr);
                route_dst.set_dst_addr(src_addr);
                route_dst.set_src_cepid(dst_cepid);
                route_dst.set_dst_cepid(src_cepid);
                route_dst.set_next_hop(*src);

                rib->send_to_dst_node(std::move(m_src), *src, &route_src);
                rib->send_to_dst_node(std::move(m_dst), *dst, &route_dst);
            }
        }

        auto cbuf  = std::unique_ptr<char[]>(new char[sizeof(Command)]);
        Command *c = reinterpret_cast<Command *>(cbuf.get());
        memset(c, 0, sizeof(*c));

        /* Fill in the command struct (already serialized). */
        strncpy(c->flow_id, flow_id.c_str(), sizeof(c->flow_id) - 1);
        c->src_addr  = src_addr;
        c->dst_addr  = dst_addr;
        c->src_cepid = src_cepid;
        c->dst_cepid = dst_cepid;
        c->opcode    = Command::OpcodeReserve;

        /* Return the command to the caller. */
        commands->push_back(make_pair(std::move(cbuf), nullptr));

        {
            auto m = utils::make_unique<CDAPMessage>();

            m->op_code   = gpb::M_CREATE_R;
            m->obj_name  = rm->obj_name + "/" + to_string(invoke_id);
            m->obj_class = FlowObjClass;
            m->invoke_id = rm->invoke_id;

            m->set_obj_value(objbuf, objlen);

            rib->send_to_dst_node(std::move(m), freq.src_ipcp());
        }
        pending.erase(rm->invoke_id);
    } else if (rm->op_code == gpb::M_DELETE) {
        std::string flow_id;
        rm->get_obj_value(flow_id);
        auto f = table.find(flow_id);
        if (f != table.end()) {
            auto e = f->second;
            rlm_addr_t req_addr;
            rlm_addr_t remote_addr;
            req_addr    = rib->lookup_node_address(e.from);
            remote_addr = src_addr == req_addr ? rib->lookup_node_address(e.to)
                                               : req_addr;

            auto m = utils::make_unique<CDAPMessage>();

            m->op_code   = gpb::M_DELETE_R;
            m->obj_name  = rm->obj_name;
            m->obj_class = FlowObjClass;
            m->invoke_id = rm->invoke_id;

            auto cbuf  = std::unique_ptr<char[]>(new char[sizeof(Command)]);
            Command *c = reinterpret_cast<Command *>(cbuf.get());
            memset(c, 0, sizeof(*c));

            /* Fill in the command struct (already serialized). */
            c->opcode = Command::OpcodeFree;
            strncpy(c->flow_id, flow_id.c_str(), sizeof(c->flow_id) - 1);

            /* Return the command to the caller. */
            commands->push_back(make_pair(std::move(cbuf), std::move(m)));

            auto fm = utils::make_unique<CDAPMessage>();

            fm->op_code   = rm->op_code;
            fm->obj_class = FlowObjClass;
            fm->obj_name  = rm->obj_name;

            rib->send_to_dst_addr(std::move(fm), remote_addr);

            rlm_addr_t src_addr   = e.src_addr;
            rlm_addr_t dst_addr   = e.dst_addr;
            rlm_cepid_t src_cepid = e.src_cepid;
            rlm_cepid_t dst_cepid = e.dst_cepid;

            for (auto src = e.path.begin(); std::next(src) != e.path.end();
                 ++src) {
                auto dst = std::next(src);

                if (!(src == e.path.begin() &&
                      std::next(dst) == e.path.end())) {
                    auto m_src       = utils::make_unique<CDAPMessage>();
                    m_src->op_code   = gpb::M_DELETE;
                    m_src->obj_name  = Routing::TableName;
                    m_src->obj_class = BwResRouting::PerFlowObjClass;

                    auto m_dst       = utils::make_unique<CDAPMessage>();
                    m_dst->op_code   = gpb::M_DELETE;
                    m_dst->obj_name  = Routing::TableName;
                    m_dst->obj_class = BwResRouting::PerFlowObjClass;

                    gpb::BwResRoute route_src;
                    gpb::BwResRoute route_dst;

                    route_src.set_src_addr(src_addr);
                    route_src.set_dst_addr(dst_addr);
                    route_src.set_src_cepid(src_cepid);
                    route_src.set_dst_cepid(dst_cepid);
                    route_src.set_next_hop(*dst);

                    route_dst.set_src_addr(dst_addr);
                    route_dst.set_dst_addr(src_addr);
                    route_dst.set_src_cepid(dst_cepid);
                    route_dst.set_dst_cepid(src_cepid);
                    route_dst.set_next_hop(*src);

                    rib->send_to_dst_node(std::move(m_src), *src, &route_src);
                    rib->send_to_dst_node(std::move(m_dst), *dst, &route_dst);
                }
            }
        }
    } else {
        UPE(uipcp, "M_CREATE(fa) or M_DELETE(fa) expected\n");
        return 0;
    }

    return 0;
}

int
BwResFlowAllocator::Client::allocate(const FlowRequest &freq)
{
    auto m = utils::make_unique<CDAPMessage>();

    m->m_create(ObjClass, TableName + "/" + to_string(freq.invoke_id));

    std::string flow_id(freq.gpb.src_ipcp() + freq.gpb.dst_ipcp() +
                        std::to_string(freq.gpb.src_port()));

    rib->obj_serialize(m.get(), &freq.gpb);

    auto timeout =
        rib->get_param_value<Msecs>(FlowAllocator::Prefix, "cli-timeout");
    auto pr = utils::make_unique<PendingReq>(m->op_code, timeout, flow_id);
    int ret = send_to_replicas(std::move(m), std::move(pr), OpSemantics::Put);

    if (ret) {
        return ret;
    }

    UPI(rib->uipcp,
        "Issued flow bandwidth reservation request from '%s' to '%s' of "
        "bandwidth '%u (invoke_id=%d)\n",
        freq.gpb.src_ipcp().c_str(), freq.gpb.dst_ipcp().c_str(),
        freq.flowcfg.dtcp.bandwidth, freq.invoke_id);

    return 0;
}

int
BwResFlowAllocator::Client::client_process_rib_msg(
    const CDAPMessage *rm, CeftClient::PendingReq *const bpr,
    rlm_addr_t src_addr)
{
    struct uipcp *uipcp = rib->uipcp;

    switch (rm->op_code) {
    /* Get a flow reservation id */
    case gpb::M_CREATE_R: {
        if (rm->result) {
            UPD(uipcp, "Flow reservation failed to reserve bandwidth [%s]\n",
                rm->result_reason.c_str());
        } else {
            UPD(uipcp, "Flow reservation reserved bandwidth successfully\n");
        }
        int invoke_id = stoi(rm->obj_name.substr(rm->obj_name.rfind("/") + 1));
        return fa->flows_handler_create_r(rm, invoke_id);

        break;
    }
    case gpb::M_DELETE_R: {
        break;
    }
    default:
        assert(false);
    }

    return 0;
}

void
BwResFlowAllocator::Replica::dump(std::stringstream &ss) const
{
    ss << "Flow reservation table:" << std::endl;
    for (const auto &kv : table) {
        ss << "    " << std::setw(20) << kv.first;
        ss << ": " << kv.second.from << "->" << kv.second.to << " (";
        for (auto v : kv.second.path) {
            ss << v << ",";
        }
        ss << ") : " << kv.second.bw << std::endl;
    }
}

/* (1) Initiator FA <-- Initiator application : FA_REQ */
int
BwResFlowAllocator::fa_req(struct rl_kmsg_fa_req *req,
                           const std::string &remote_node)
{
    auto freq        = utils::make_unique<FlowRequest>();
    string dest_appl = string(req->remote_appl);
    std::unique_ptr<CDAPMessage> m;
    struct rl_flow_config flowcfg;
    rlm_qosid_t qos_id = 0; /* default */
    gpb::ConnId *conn_id;

    if (req->flowspec.version != RINA_FLOW_SPEC_VERSION) {
        UPE(rib->uipcp,
            "Version mismatch in flow spec (got %u, "
            "expected %u)\n",
            req->flowspec.version, RINA_FLOW_SPEC_VERSION);
        return -1;
    }

    if (!req->flowspec.avg_bandwidth) {
        if (rib->get_param_value<bool>(FlowAllocator::Prefix,
                                       "reject-inf-bw")) {
            return uipcp_issue_fa_resp_arrived(rib->uipcp, req->local_port,
                                               /*remote_port=*/0,
                                               /*remote_cep=*/0,
                                               /*qos_id=*/0, /*remote_addr=*/0,
                                               /*response=*/1, /*cfg=*/nullptr);
        } else {
            req->flowspec.avg_bandwidth =
                rib->get_param_value<int>(FlowAllocator::Prefix, "default-bw");
        }
    }

    /* Translate the flow specification into a local flow configuration
     * and the corresponding QoS id. */
    flowspec2flowcfg(&req->flowspec, &flowcfg, &qos_id);

    flowcfg2policies(&flowcfg, freq.get());

    freq->gpb.set_allocated_src_app(
        apname2gpb(req->local_appl)); /* req->local_appl may be nullptr */
    freq->gpb.set_allocated_dst_app(apname2gpb(dest_appl));
    freq->gpb.set_src_port(req->local_port);
    freq->gpb.set_dst_port(0);
    freq->gpb.set_src_ipcp(rib->myname);
    freq->gpb.set_dst_ipcp(remote_node);
    conn_id = freq->gpb.add_connections();
    conn_id->set_qosid(qos_id);
    conn_id->set_src_cep(req->local_cep);
    conn_id->set_dst_cep(0);
    freq->gpb.set_cur_conn_idx(0);
    freq->gpb.set_state(true);
    freq->uid = req->uid; /* on initiator side, uid is generated by
                           * the kernel, we just store it */
    freq->flowcfg = flowcfg;
    freq->gpb.set_max_create_flow_retries(3);
    freq->gpb.set_create_flow_retries(0);
    freq->gpb.set_hop_cnt(0);

    freq->invoke_id = rib->invoke_id_mgr.get_invoke_id();

    freq->flags = RL_FLOWREQ_INITIATOR | RL_FLOWREQ_SEND_DEL;

    if (client->allocate(*freq)) {
        UPE(rib->uipcp, "Could not reserve requested bandwidth for the flow\n");
        return -1;
    }

    flow_reqs_out[freq->invoke_id] = std::move(freq);
    rib->stats.fa_request_issued++;

    return 0;
}

int
BwResFlowAllocator::rib_handler(const CDAPMessage *rm, const MsgSrcInfo &src)
{
    if (rm->obj_class == FlowObjClass) {
        switch (rm->op_code) {
        case gpb::M_CREATE:
            return flows_handler_create(rm, src);

        case gpb::M_CREATE_R:
            return client->rib_handler(rm, src);

        case gpb::M_DELETE:
            return flows_handler_delete(rm, src);

        case gpb::M_DELETE_R:
            return client->rib_handler(rm, src);

        default:
            UPE(rib->uipcp,
                "M_CREATE, M_CREATE_R, M_DELETE or M_DELETE_R expected\n");
            break;
        }
    } else {
        return raft->rib_handler(rm, src);
    }

    return 0;
}

void
BwResFlowAllocator::dump(std::stringstream &ss) const
{
    ss << "Supported flows (Src/Dst <Appl,IPCP,port>):" << endl;
    for (const auto &kvf : flow_reqs) {
        const auto &freq = kvf.second;

        ss << "    [" << ((freq->flags & RL_FLOWREQ_INITIATOR) ? "L" : "R")
           << "]"
           << ", Src=<" << apname2string(freq->gpb.src_app()) << ","
           << freq->gpb.src_ipcp() << "," << freq->gpb.src_port() << "> Dst=<"
           << apname2string(freq->gpb.dst_app()) << "," << freq->gpb.dst_ipcp()
           << "," << freq->gpb.dst_port() << "> Connections: [";
        for (int i = 0; i < freq->gpb.connections_size(); i++) {
            ss << "<SrcCep=" << freq->gpb.connections(i).src_cep()
               << ", DstCep=" << freq->gpb.connections(i).dst_cep()
               << ", QosId=" << freq->gpb.connections(i).qosid() << "> ";
        }
        ss << "]" << endl;
    }
    ss << endl;
    if (raft) {
        raft->dump(ss);
    }
}

int
BwResFlowAllocator::Client::free(const FlowRequest &freq)
{
    std::stringstream remote_obj_name;
    std::string flow_id(freq.gpb.src_ipcp() + freq.gpb.dst_ipcp() +
                        std::to_string(freq.gpb.src_port()));
    auto m = utils::make_unique<CDAPMessage>();

    auto timeout = rib->get_param_value<Msecs>(Prefix, "cli-timeout");
    auto pr      = utils::make_unique<PendingReq>(m->op_code, timeout, flow_id);

    m = utils::make_unique<CDAPMessage>();
    remote_obj_name << TableName << "/";
    if (freq.flags & RL_FLOWREQ_INITIATOR) {
        remote_obj_name << freq.gpb.dst_port();
    } else {
        remote_obj_name << freq.gpb.src_port();
    }
    m->m_delete(ObjClass, remote_obj_name.str());

    m->set_obj_value(flow_id);

    return send_to_replicas(std::move(m), std::move(pr), OpSemantics::Put);
}

int
BwResFlowAllocator::flow_deallocated(struct rl_kmsg_flow_deallocated *req)
{
    bool send_del;

    /* Lookup the corresponding FlowRequest by port_id. */
    auto f = flow_reqs.find(req->local_port_id);
    if (f == flow_reqs.end()) {
        UPE(rib->uipcp,
            "Spurious flow deallocated notification, no object with "
            "port_id "
            "%u\n",
            req->local_port_id);
        return -1;
    }

    std::unique_ptr<FlowRequest> freq = std::move(f->second);

    flow_reqs.erase(f);
    send_del = (freq->flags & RL_FLOWREQ_SEND_DEL);

    UPV(rib->uipcp, "Removed flow request with port_id %u\n",
        req->local_port_id);

    if (!send_del) {
        return 0;
    }

    /* We should wait 2 MPL here before notifying the peer. */

    return client->free(*freq);
}

/* (2) Slave FA <-- Initiator FA : M_CREATE */
int
BwResFlowAllocator::flows_handler_create(const CDAPMessage *rm,
                                         const MsgSrcInfo &src)
{
    rlm_addr_t remote_addr;
    const char *objbuf;
    size_t objlen;

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(rib->uipcp, "M_CREATE does not contain a nested message\n");
        return 0;
    }

    auto freq = utils::make_unique<FlowRequest>();
    std::string local_appl, remote_appl;
    struct rl_flow_config flowcfg;

    freq->gpb.ParseFromArray(objbuf, objlen);
    remote_addr = src.addr;
    if (freq->gpb.connections_size() < 1) {
        std::unique_ptr<CDAPMessage> m;
        std::stringstream error_msg;

        if (freq->gpb.connections_size() < 1) {
            error_msg << "No connections specified on this flow";
        }

        UPE(rib->uipcp, "%s\n", error_msg.str().c_str());
        m = utils::make_unique<CDAPMessage>();
        m->m_create_r(ObjClass, rm->obj_name, 0, -1, error_msg.str());
        m->invoke_id = rm->invoke_id;

        return rib->send_to_dst_addr(std::move(m), remote_addr);
    }

    /* freq->gpb.dst_app() is registered with us, let's go ahead. */

    local_appl  = apname2string(freq->gpb.dst_app());
    remote_appl = apname2string(freq->gpb.src_app());
    policies2flowcfg(&flowcfg, freq.get());

    freq->invoke_id = rm->invoke_id;
    freq->flags     = RL_FLOWREQ_SEND_DEL;
    freq->uid       = kevent_id_cnt++; /* on slave side uid is generated by us,
                                        * and it is also used as 'event_id' by the
                                        * kernel */

    remote_addr = rib->lookup_node_address(freq->gpb.src_ipcp());

    uipcp_issue_fa_req_arrived(
        rib->uipcp, freq->uid, freq->gpb.src_port(),
        freq->gpb.connections(0).src_cep(), freq->gpb.connections(0).qosid(),
        remote_addr, local_appl.c_str(), remote_appl.c_str(), &flowcfg);
    leader_pending[freq->uid] = src.addr;
    flow_reqs_in[freq->uid]   = std::move(freq);
    rib->stats.fa_request_received++;

    return 0;
}

/* (3) Slave FA <-- Slave application : FA_RESP */
int
BwResFlowAllocator::fa_resp(struct rl_kmsg_fa_resp *resp)
{
    std::unique_ptr<CDAPMessage> m;
    string reason;
    int ret;

    /* Lookup the corresponding FlowRequest. */

    auto f = flow_reqs_in.find(resp->kevent_id);
    if (f == flow_reqs_in.end()) {
        UPE(rib->uipcp,
            "Spurious flow allocation response, no request for kevent_id "
            "%u\n",
            resp->kevent_id);
        return -1;
    }

    auto a = leader_pending.find(resp->kevent_id);
    if (a == leader_pending.end()) {
        UPE(rib->uipcp,
            "Spurious flow allocation response, no request for kevent_id "
            "%u\n",
            resp->kevent_id);
        return -1;
    }

    rlm_addr_t leader_addr = a->second;

    FlowRequest *freq = f->second.get();

    /* Update the freq object with the port-id and cep-id allocated by
     * the kernel. */
    freq->gpb.set_dst_port(resp->port_id);
    freq->gpb.mutable_connections(0)->set_dst_cep(resp->cep_id);

    if (resp->response) {
        reason = "Application refused the accept the flow request";
    } else {
        /* Move the freq object from the temporary map to the right one. */
        flow_reqs[resp->port_id] = std::move(f->second);
    }

    m = utils::make_unique<CDAPMessage>();
    m->m_create_r(ObjClass, TableName, 0, resp->response ? -1 : 0, reason);
    m->invoke_id = freq->invoke_id;

    ret = rib->send_to_dst_addr(std::move(m), leader_addr, &freq->gpb);
    flow_reqs_in.erase(f); /* freq cannot be used after this instruction */
    leader_pending.erase(a);
    rib->stats.fa_response_issued++;

    return ret;
}

int
BwResFlowAllocator::flows_handler_delete(const CDAPMessage *rm,
                                         const MsgSrcInfo &src)
{
    /* rlm_addr_t expected_src_addr; */
    rl_port_t local_port;
    stringstream decode;
    string objname;

    decode << rm->obj_name.substr(TableName.size() + 1);
    decode >> local_port;

    /* Lookup the corresponding FlowRequest by port_id. */
    auto f = flow_reqs.find(local_port);
    if (f == flow_reqs.end()) {
        UPV(rib->uipcp, "No flow port_id %u (may be already deleted locally)\n",
            local_port);
        return 0;
    }

    FlowRequest *freq = f->second.get();

    /* expected_src_addr = rib->lookup_node_address( */
    /*     (freq->flags & RL_FLOWREQ_INITIATOR) ? freq->gpb.dst_ipcp() */
    /*                                          : freq->gpb.src_ipcp()); */
    /* if (src.addr != expected_src_addr) { */
    /*     UPW(rib->uipcp, */
    /*         "Remote flow deallocation from unmatching address " */
    /*         "'%lu' (expected=%lu)\n", */
    /*         (long unsigned)src.addr, (long unsigned)expected_src_addr); */
    /*     return 0; */
    /* } */

    /* We received a delete request from the peer, so we won't need to send
     * him a delete request. */
    freq->flags &= ~RL_FLOWREQ_SEND_DEL;

    return uipcp_issue_flow_dealloc(rib->uipcp, local_port, freq->uid);
}

void
UipcpRib::fa_lib_init()
{
    UipcpRib::policy_register(
        FlowAllocator::Prefix, "local",
        [](UipcpRib *rib) {
            return utils::make_unique<LocalFlowAllocator>(rib);
        },
        {FlowAllocator::TableName},
        {{"force-flow-control", PolicyParam(false)},
         {"max-cwq-len",
          PolicyParam(LocalFlowAllocator::kFlowControlMaxCwqLen)},
         {"initial-credit",
          PolicyParam(LocalFlowAllocator::kFlowControlInitialCredit)},
         {"initial-a",
          PolicyParam(Msecs(int(LocalFlowAllocator::kATimerMsecsDflt)))},
         {"initial-rtx-timeout",
          PolicyParam(Msecs(int(LocalFlowAllocator::kRtxTimerMsecsDflt)))},
         {"max-rtxq-len", PolicyParam(LocalFlowAllocator::kRtxQueueMaxLen)}});

    using PolicyTuple =
        std::tuple<const std::string &, const std::string &,
                   std::function<std::unique_ptr<rlite::Component>(UipcpRib *)>,
                   std::vector<std::string>,
                   std::vector<std::pair<std::string, rlite::PolicyParam>>,
                   std::vector<std::pair<std::string, std::string>>>;

    UipcpRib::policy_register_group(
        {PolicyTuple(
             FlowAllocator::Prefix, "bw-res",
             [](UipcpRib *rib) {
                 return utils::make_unique<BwResFlowAllocator>(rib);
             },
             {FlowAllocator::TableName},
             {{"force-flow-control", PolicyParam(false)},
              {"max-cwq-len",
               PolicyParam(BwResFlowAllocator::kFlowControlMaxCwqLen)},
              {"initial-credit",
               PolicyParam(BwResFlowAllocator::kFlowControlInitialCredit)},
              {"initial-a",
               PolicyParam(Msecs(int(BwResFlowAllocator::kATimerMsecsDflt)))},
              {"initial-rtx-timeout",
               PolicyParam(Msecs(int(BwResFlowAllocator::kRtxTimerMsecsDflt)))},
              {"max-rtxq-len",
               PolicyParam(BwResFlowAllocator::kRtxQueueMaxLen)},
              {"replicas", PolicyParam(string())},
              {"cli-timeout", PolicyParam(Secs(int(CeftClient::kTimeoutSecs)))},
              {"raft-election-timeout", PolicyParam(Secs(1))},
              {"raft-heartbeat-timeout",
               PolicyParam(Msecs(int(CeftReplica::kHeartBeatTimeoutMsecs)))},
              {"raft-rtx-timeout",
               PolicyParam(Msecs(int(CeftReplica::kRtxTimeoutMsecs)))},
              {"reject-inf-bw", PolicyParam(false)},
              {"default-bw",
               PolicyParam(BwResFlowAllocator::DefaultBandwidth)}},
             {}),

         PolicyTuple(
             Routing::Prefix, "bw-res-link-state",
             [](UipcpRib *rib) {
                 return utils::make_unique<BwResRouting>(rib, false);
             },
             {Routing::TableName},
             {{"age-incr-intval",
               PolicyParam(Secs(int(BwResRouting::kAgeIncrIntvalSecs)))},
              {"age-max", PolicyParam(Secs(int(BwResRouting::kAgeMaxSecs)))}},
             {})});
}

} // namespace rlite
