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

#include "uipcp-normal.hpp"

using namespace std;

struct FlowRequest : public gpb::FlowRequest {
    FlowRequest() = default;
    RL_NONCOPIABLE(FlowRequest);
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
uipcp_rib::fa_req(struct rl_kmsg_fa_req *req)
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

        return uipcp_issue_fa_resp_arrived(
            uipcp, req->local_port, 0 /* don't care */, 0 /* don't care */,
            0 /* don't care */, 1, nullptr);
    }

    if (!remote_node.empty()) {
        /* DFT lookup request was served immediately, we can go ahead. */
        return fa->fa_req(req, remote_node);
    }

    /* We need to wait for the DFT lookup to complete before we can go
     * ahead. Store the FA request in a list of pending request. */

    /* Make a copy of the request, with some move semantic. */
    std::unique_ptr<struct rl_kmsg_fa_req> reqcopy =
        make_unique<struct rl_kmsg_fa_req>();
    *reqcopy         = *req;
    req->local_appl  = nullptr;
    req->remote_appl = nullptr;
    req->dif_name    = nullptr;
    pending_fa_reqs[appl_name].push_back(std::move(reqcopy));

    return 0;
}

void
uipcp_rib::dft_lookup_resolved(const std::string &appl_name,
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
    }
    for (auto &fr : mit->second) {
        if (remote_node.empty()) {
            /* Return a negative flow allocation response. */
            uipcp_issue_fa_resp_arrived(uipcp, fr->local_port,
                                        0 /* don't care */, 0 /* don't care */,
                                        0 /* don't care */, 1, nullptr);
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
    LocalFlowAllocator(uipcp_rib *_ur) : FlowAllocator(_ur) {}
    ~LocalFlowAllocator() {}

    void dump(std::stringstream &ss) const override;
    void dump_memtrack(std::stringstream &ss) const override;

    std::unordered_map<std::string, std::unique_ptr<FlowRequest>> flow_reqs;
    std::unordered_map<unsigned int, std::unique_ptr<FlowRequest>>
        flow_reqs_tmp;

    int fa_req(struct rl_kmsg_fa_req *req,
               const std::string &remote_node) override;
    int fa_resp(struct rl_kmsg_fa_resp *resp) override;

    int flow_deallocated(struct rl_kmsg_flow_deallocated *req) override;

    int flows_handler_create(const CDAPMessage *rm) override;
    int flows_handler_create_r(const CDAPMessage *rm) override;
    int flows_handler_delete(const CDAPMessage *rm) override;

private:
    void flowspec2flowcfg(const struct rina_flow_spec *spec,
                          struct rl_flow_config *cfg) const;
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

    freq->set_allocated_qos(qos);
    freq->set_allocated_policies(policies);

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
    const gpb::QosSpec &qos    = freq->qos();
    const gpb::ConnPolicies &p = freq->policies();

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
                                     struct rl_flow_config *cfg) const
{
    bool force_flow_control =
        rib->get_param_value<bool>(FlowAllocator::Prefix, "force-flow-control");
    unsigned initial_a =
        rib->get_param_value<int>(FlowAllocator::Prefix, "initial-a");

    memset(cfg, 0, sizeof(*cfg));

    cfg->max_sdu_gap       = spec->max_sdu_gap;
    cfg->in_order_delivery = spec->in_order_delivery;
    cfg->msg_boundaries    = spec->msg_boundaries;
    cfg->dtcp.bandwidth    = spec->avg_bandwidth;

    if (spec->max_sdu_gap == 0) {
        /* We need retransmission control. */
        cfg->dtcp.flags |= DTCP_CFG_RTX_CTRL;
        cfg->in_order_delivery            = 1;
        cfg->dtcp.rtx.max_time_to_retry   = 15; /* unused for now */
        cfg->dtcp.rtx.data_rxms_max       = RL_DATA_RXMS_MAX_DFLT;
        cfg->dtcp.rtx.initial_rtx_timeout = rib->get_param_value<int>(
            FlowAllocator::Prefix, "initial-rtx-timeout");
        cfg->dtcp.rtx.max_rtxq_len =
            rib->get_param_value<int>(FlowAllocator::Prefix, "max-rtxq-len");
        cfg->dtcp.initial_a = initial_a;
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
        cfg->dtcp.initial_a  = initial_a;
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
    std::unique_ptr<CDAPMessage> m;
    rlm_addr_t remote_addr;
    auto freq = make_unique<FlowRequest>();
    gpb::ConnId *conn_id;
    stringstream obj_name;
    string cubename;
    struct rl_flow_config flowcfg;
    string dest_appl = string(req->remote_appl);
    int ret;

    if (req->flowspec.version != RINA_FLOW_SPEC_VERSION) {
        UPE(rib->uipcp,
            "Version mismatch in flow spec (got %u, "
            "expected %u)\n",
            req->flowspec.version, RINA_FLOW_SPEC_VERSION);
        return -1;
    }

    remote_addr = rib->lookup_node_address(remote_node);
    if (remote_addr == RL_ADDR_NULL) {
        UPE(rib->uipcp, "Cannot find address for node %s\n",
            remote_node.c_str());
        return -1;
    }

    freq->set_allocated_src_app(
        apname2gpb(req->local_appl)); /* req->local_appl may be nullptr */
    freq->set_allocated_dst_app(apname2gpb(dest_appl));
    freq->set_src_port(req->local_port);
    freq->set_dst_port(0);
    freq->set_src_addr(rib->myaddr);
    freq->set_dst_addr(remote_addr);
    conn_id = freq->add_connections();
    conn_id->set_qosid(0);
    conn_id->set_src_cep(req->local_cep);
    conn_id->set_dst_cep(0);
    freq->set_cur_conn_idx(0);
    freq->set_state(true);
    freq->uid = req->uid; /* on initiator side, uid is generated by
                           * the kernel, we just store it */

#ifndef RL_USE_QOS_CUBES
    /* Translate the flow specification into a local flow configuration. */
    flowspec2flowcfg(&req->flowspec, &flowcfg);
#else  /* RL_USE_QOS_CUBES */
    map<string, struct rl_flow_config>::iterator qcmi;

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

    freq->flowcfg = flowcfg;
    freq->set_max_create_flow_retries(3);
    freq->set_create_flow_retries(0);
    freq->set_hop_cnt(0);

    obj_name << TableName << "/" << freq->src_addr() << "-" << req->local_port;

    m = make_unique<CDAPMessage>();
    m->m_create(FlowObjClass, obj_name.str());

    freq->invoke_id = 0; /* invoke_id is actually set in send_to_dst_addr() */
    freq->flags     = RL_FLOWREQ_INITIATOR | RL_FLOWREQ_SEND_DEL;

    ret = rib->send_to_dst_addr(std::move(m), freq->dst_addr(), freq.get());
    if (ret) {
        return ret;
    }
    flow_reqs[obj_name.str() + string("L")] = std::move(freq);

    return 0;
}

/* (3) Slave FA <-- Slave application : FA_RESP */
int
LocalFlowAllocator::fa_resp(struct rl_kmsg_fa_resp *resp)
{
    std::unique_ptr<CDAPMessage> m;
    stringstream obj_name;
    string reason;
    int ret;

    /* Lookup the corresponding FlowRequest. */

    auto f = flow_reqs_tmp.find(resp->kevent_id);

    if (f == flow_reqs_tmp.end()) {
        UPE(rib->uipcp,
            "Spurious flow allocation response, no request for kevent_id %u\n",
            resp->kevent_id);
        return -1;
    }

    std::unique_ptr<FlowRequest> &freq = f->second;

    /* Update the freq object with the port-id and cep-id allocated by
     * the kernel. */
    freq->set_dst_port(resp->port_id);
    freq->mutable_connections(0)->set_dst_cep(resp->cep_id);

    obj_name << TableName << "/" << freq->src_addr() << "-" << freq->src_port();

    if (resp->response) {
        reason = "Application refused the accept the flow request";
    }

    m = make_unique<CDAPMessage>();
    m->m_create_r(FlowObjClass, obj_name.str(), 0, resp->response ? -1 : 0,
                  reason);
    m->invoke_id = freq->invoke_id;

    ret = rib->send_to_dst_addr(std::move(m), freq->src_addr(), freq.get());
    if (!resp->response) {
        /* Move the freq object from the temporary map to the right one. */
        flow_reqs[obj_name.str() + string("R")] = std::move(freq);
    }
    flow_reqs_tmp.erase(f); /* first std::move(), then erase. */

    return ret;
}

/* (2) Slave FA <-- Initiator FA : M_CREATE */
int
LocalFlowAllocator::flows_handler_create(const CDAPMessage *rm)
{
    const char *objbuf;
    size_t objlen;

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(rib->uipcp, "M_CREATE does not contain a nested message\n");
        return 0;
    }

    auto freq = make_unique<FlowRequest>();
    std::string local_appl, remote_appl;
    struct rl_flow_config flowcfg;

    freq->ParseFromArray(objbuf, objlen);
    freq->flags = 0;
    if (freq->connections_size() < 1) {
        std::unique_ptr<CDAPMessage> m;

        UPE(rib->uipcp, "No connections specified on this flow\n");
        m = make_unique<CDAPMessage>();
        m->m_create_r(rm->obj_class, rm->obj_name, 0, -1,
                      "No connections specified");
        m->invoke_id = rm->invoke_id;

        return rib->send_to_dst_addr(std::move(m), freq->src_addr());
    }

    /* freq->dst_app() is registered with us, let's go ahead. */

    local_appl  = apname2string(freq->dst_app());
    remote_appl = apname2string(freq->src_app());
    policies2flowcfg(&flowcfg, freq.get());

    freq->invoke_id = rm->invoke_id;
    freq->flags     = RL_FLOWREQ_SEND_DEL;
    freq->uid = kevent_id_cnt++; /* on slave side uid is generated by us, and
                                  * it is also used as 'event_id' by the
                                  * kernel */
    uipcp_issue_fa_req_arrived(
        rib->uipcp, freq->uid, freq->src_port(), freq->connections(0).src_cep(),
        freq->src_addr(), local_appl.c_str(), remote_appl.c_str(), &flowcfg);
    flow_reqs_tmp[freq->uid] = std::move(freq);

    return 0;
}

/* (4) Initiator FA <-- Slave FA : M_CREATE_R */
int
LocalFlowAllocator::flows_handler_create_r(const CDAPMessage *rm)
{
    const char *objbuf;
    size_t objlen;

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(rib->uipcp, "M_CREATE_R does not contain a nested message\n");
        return 0;
    }

    auto f = flow_reqs.find(rm->obj_name + string("L"));

    if (f == flow_reqs.end()) {
        UPE(rib->uipcp,
            "M_CREATE_R for '%s' does not match any pending request\n",
            rm->obj_name.c_str());
        return 0;
    }

    std::unique_ptr<FlowRequest> &freq = f->second;
    FlowRequest remote_freq;

    remote_freq.ParseFromArray(objbuf, objlen);
    /* Update the local freq object with the remote one. */
    freq->set_dst_port(remote_freq.dst_port());
    freq->mutable_connections(0)->set_dst_cep(
        remote_freq.connections(0).dst_cep());

    return uipcp_issue_fa_resp_arrived(
        rib->uipcp, freq->src_port(), freq->dst_port(),
        freq->connections(0).dst_cep(), freq->dst_addr(), rm->result ? 1 : 0,
        &freq->flowcfg);
}

int
LocalFlowAllocator::flow_deallocated(struct rl_kmsg_flow_deallocated *req)
{
    stringstream obj_name_ext;
    string obj_name;
    rlm_addr_t remote_addr;
    std::unique_ptr<CDAPMessage> m;
    bool send_del;

    /* Lookup the corresponding FlowRequest, depending on whether we were
     * the initiator or not. */
    if (req->initiator) {
        obj_name_ext << TableName << "/" << rib->myaddr << "-"
                     << req->local_port_id;
        obj_name = obj_name_ext.str();
        obj_name_ext << "L";
    } else {
        obj_name_ext << TableName << "/" << req->remote_addr << "-"
                     << req->remote_port_id;
        obj_name = obj_name_ext.str();
        obj_name_ext << "R";
    }

    auto f = flow_reqs.find(obj_name_ext.str());
    if (f == flow_reqs.end()) {
        UPE(rib->uipcp,
            "Spurious flow deallocated notification, no object with name %s\n",
            obj_name_ext.str().c_str());
        return -1;
    }

    std::unique_ptr<FlowRequest> &freq = f->second;

    /* We were the initiator. */
    assert(!!(freq->flags & RL_FLOWREQ_INITIATOR) == !!req->initiator);
    remote_addr = req->initiator ? freq->dst_addr() : freq->src_addr();
    send_del    = (freq->flags & RL_FLOWREQ_SEND_DEL);
    flow_reqs.erase(f);

    UPD(rib->uipcp, "Removed flow request %s [port %u]\n",
        obj_name_ext.str().c_str(), req->local_port_id);

    if (!send_del) {
        return 0;
    }

    /* We should wait 2 MPL here before notifying the peer. */
    m = make_unique<CDAPMessage>();
    m->m_delete(FlowObjClass, obj_name);

    return rib->send_to_dst_addr(std::move(m), remote_addr);
}

int
LocalFlowAllocator::flows_handler_delete(const CDAPMessage *rm)
{
    rl_port_t local_port;
    stringstream decode;
    string objname;
    unsigned addr, port;
    char separator;

    decode << rm->obj_name.substr(TableName.size() + 1);
    decode >> addr >> separator >> port;
    /* TODO the following is wrong when flows are local to the node, as
     * local and remote address are the same. */
    if (addr == rib->myaddr) {
        /* We were the initiator. */
        objname = rm->obj_name + string("L");
    } else {
        /* We were the target. */
        objname = rm->obj_name + string("R");
    }
    auto f = flow_reqs.find(objname);

    if (f == flow_reqs.end()) {
        UPV(rib->uipcp, "Flow '%s' already deleted locally\n", objname.c_str());
        return 0;
    }

    std::unique_ptr<FlowRequest> &freq = f->second;

    if (addr == rib->myaddr) {
        /* We were the initiator. */
        assert(freq->flags & RL_FLOWREQ_INITIATOR);
    } else {
        /* We were the target. */
        assert(!(freq->flags & RL_FLOWREQ_INITIATOR));
    }

    local_port = (freq->flags & RL_FLOWREQ_INITIATOR) ? freq->src_port()
                                                      : freq->dst_port();

    /* We received a delete request from the peer, so we won't need to send
     * him a delete request. */
    freq->flags &= ~RL_FLOWREQ_SEND_DEL;

    return uipcp_issue_flow_dealloc(rib->uipcp, local_port, freq->uid);
}

int
FlowAllocator::rib_handler(const CDAPMessage *rm,
                           std::shared_ptr<NeighFlow> const &nf,
                           std::shared_ptr<Neighbor> const &neigh,
                           rlm_addr_t src_addr)
{
    switch (rm->op_code) {
    case gpb::M_CREATE:
        return flows_handler_create(rm);

    case gpb::M_CREATE_R:
        return flows_handler_create_r(rm);

    case gpb::M_DELETE:
        return flows_handler_delete(rm);

    case gpb::M_DELETE_R:
        UPE(rib->uipcp, "NOT SUPPORTED YET");
        assert(0);
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
    ss << "Supported flows:" << endl;
    for (const auto &kvf : flow_reqs) {
        const auto &freq = kvf.second;

        ss << "    [" << ((freq->flags & RL_FLOWREQ_INITIATOR) ? "L" : "R")
           << "]"
           << ", Src=" << apname2string(freq->src_app())
           << ", Dst=" << apname2string(freq->dst_app())
           << ", SrcAddr:Port=" << freq->src_addr() << ":" << freq->src_port()
           << ", DstAddr:Port=" << freq->dst_addr() << ":" << freq->dst_port()
           << ", Connections: [";
        for (int i = 0; i < freq->connections_size(); i++) {
            ss << "<SrcCep=" << freq->connections(i).src_cep()
               << ", DstCep=" << freq->connections(i).dst_cep()
               << ", QosId=" << freq->connections(i).qosid() << "> ";
        }
        ss << "]" << endl;
    }
    ss << endl;
}

void
LocalFlowAllocator::dump_memtrack(std::stringstream &ss) const
{
    ss << endl << "Temporary tables:" << endl;
    ss << "    " << flow_reqs_tmp.size()
       << " elements in the "
          "temporary flow request table"
       << endl;
}

void
uipcp_rib::fa_lib_init()
{
    available_policies[FlowAllocator::Prefix].insert(PolicyBuilder(
        "local",
        [](uipcp_rib *rib) { rib->fa = make_unique<LocalFlowAllocator>(rib); },
        {FlowAllocator::TableName}));
}
