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

int
uipcp_rib::fa_req(struct rl_kmsg_fa_req *req)
{
    rlm_addr_t remote_addr;
    std::string appl_name;
    int ret;

    if (!req->remote_appl) {
        UPE(uipcp, "Null remote application name\n");
        return -1;
    }

    appl_name = string(req->remote_appl);

    /* Lookup the DFT. */
    ret = dft->lookup_req(appl_name, &remote_addr,
                          /* no preference */ 0, req->cookie);
    if (ret) {
        /* Return a negative flow allocation response immediately. */
        UPI(uipcp, "No DFT matching entry for destination %s\n",
            req->remote_appl);

        return uipcp_issue_fa_resp_arrived(
            uipcp, req->local_port, 0 /* don't care */, 0 /* don't care */,
            0 /* don't care */, 1, nullptr);
    }

    if (remote_addr != RL_ADDR_NULL) {
        /* DFT lookup request was served immediately, we can go ahead. */
        return fa->fa_req(req, remote_addr);
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
                               rlm_addr_t remote_addr)
{
    auto mit = pending_fa_reqs.find(appl_name);

    if (mit == pending_fa_reqs.end()) {
        UPV(uipcp, "DFT lookup for '%s' resolved, but no pending requests\n",
            appl_name.c_str());
        return;
    }

    /* Go ahead with all the flow allocation requests that were pending
     * waiting for the DFT to resolve this name. */
    if (remote_addr == RL_ADDR_NULL) {
        UPI(uipcp, "No DFT matching entry for destination %s\n",
            appl_name.c_str());
    }
    for (auto &fr : mit->second) {
        if (remote_addr == RL_ADDR_NULL) {
            /* Return a negative flow allocation response. */
            uipcp_issue_fa_resp_arrived(uipcp, fr->local_port,
                                        0 /* don't care */, 0 /* don't care */,
                                        0 /* don't care */, 1, nullptr);
        } else {
            fa->fa_req(fr.get(), remote_addr);
        }
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(fr.get()));
    }
    pending_fa_reqs.erase(mit);
}

class LocalFlowAllocator : public FlowAllocator {
public:
    RL_NODEFAULT_NONCOPIABLE(LocalFlowAllocator);
    LocalFlowAllocator(struct uipcp_rib *_ur) : FlowAllocator(_ur) {}
    ~LocalFlowAllocator() {}

    void dump(std::stringstream &ss) const override;
    void dump_memtrack(std::stringstream &ss) const override;

    std::unordered_map<std::string, FlowRequest> flow_reqs;
    std::unordered_map<unsigned int, FlowRequest> flow_reqs_tmp;

    int fa_req(struct rl_kmsg_fa_req *req, rlm_addr_t remote_addr) override;
    int fa_resp(struct rl_kmsg_fa_resp *resp) override;

    int flow_deallocated(struct rl_kmsg_flow_deallocated *req) override;

    int flows_handler_create(const CDAPMessage *rm) override;
    int flows_handler_create_r(const CDAPMessage *rm) override;
    int flows_handler_delete(const CDAPMessage *rm) override;

private:
    void flowspec2flowcfg(const struct rina_flow_spec *spec,
                          struct rl_flow_config *cfg) const;
    void policies2flowcfg(struct rl_flow_config *cfg, const QosSpec &q,
                          const ConnPolicies &p);
};

/* Translate a local flow configuration into the standard
 * representation to be used in the FlowRequest CDAP
 * message. */
static void
flowcfg2policies(const struct rl_flow_config *cfg, QosSpec &q, ConnPolicies &p)
{
    q.partial_delivery  = !cfg->msg_boundaries;
    q.in_order_delivery = cfg->in_order_delivery;
    q.max_sdu_gap       = cfg->max_sdu_gap;
    q.avg_bw            = cfg->dtcp.bandwidth;

    p.dtcp_present    = cfg->dtcp_present;
    p.initial_a_timer = cfg->dtcp.initial_a; /* name mismatch... */

    p.dtcp_cfg.flow_ctrl = cfg->dtcp.flow_control;
    p.dtcp_cfg.rtx_ctrl  = cfg->dtcp.rtx_control;

    p.dtcp_cfg.flow_ctrl_cfg.fc_type = cfg->dtcp.fc.fc_type;
    if (cfg->dtcp.fc.fc_type == RLITE_FC_T_WIN) {
        p.dtcp_cfg.flow_ctrl_cfg.win.max_cwq_len =
            cfg->dtcp.fc.cfg.w.max_cwq_len;
        p.dtcp_cfg.flow_ctrl_cfg.win.initial_credit =
            cfg->dtcp.fc.cfg.w.initial_credit;

    } else if (cfg->dtcp.fc.fc_type == RLITE_FC_T_RATE) {
        p.dtcp_cfg.flow_ctrl_cfg.rate.sending_rate =
            cfg->dtcp.fc.cfg.r.sending_rate;
        p.dtcp_cfg.flow_ctrl_cfg.rate.time_period =
            cfg->dtcp.fc.cfg.r.time_period;
    }

    p.dtcp_cfg.rtx_ctrl_cfg.max_time_to_retry = cfg->dtcp.rtx.max_time_to_retry;
    p.dtcp_cfg.rtx_ctrl_cfg.data_rxmsn_max =
        cfg->dtcp.rtx.data_rxms_max; /* mismatch... */
    p.dtcp_cfg.rtx_ctrl_cfg.initial_tr = cfg->dtcp.rtx.initial_tr;
}

/* Translate a standard flow policies specification from FlowRequest
 * CDAP message into a local flow configuration. */
void
LocalFlowAllocator::policies2flowcfg(struct rl_flow_config *cfg,
                                     const QosSpec &q, const ConnPolicies &p)
{
    cfg->msg_boundaries    = !q.partial_delivery;
    cfg->in_order_delivery = q.in_order_delivery;
    cfg->max_sdu_gap       = q.max_sdu_gap;
    cfg->dtcp.bandwidth    = q.avg_bw;

    cfg->dtcp_present   = p.dtcp_present;
    cfg->dtcp.initial_a = p.initial_a_timer;

    cfg->dtcp.flow_control = p.dtcp_cfg.flow_ctrl;
    cfg->dtcp.rtx_control  = p.dtcp_cfg.rtx_ctrl;

    cfg->dtcp.fc.fc_type = p.dtcp_cfg.flow_ctrl_cfg.fc_type;
    if (cfg->dtcp.fc.fc_type == RLITE_FC_T_WIN) {
        cfg->dtcp.fc.cfg.w.max_cwq_len =
            p.dtcp_cfg.flow_ctrl_cfg.win.max_cwq_len;
        cfg->dtcp.fc.cfg.w.initial_credit =
            p.dtcp_cfg.flow_ctrl_cfg.win.initial_credit;

    } else if (cfg->dtcp.fc.fc_type == RLITE_FC_T_RATE) {
        cfg->dtcp.fc.cfg.r.sending_rate =
            p.dtcp_cfg.flow_ctrl_cfg.rate.sending_rate;
        cfg->dtcp.fc.cfg.r.time_period =
            p.dtcp_cfg.flow_ctrl_cfg.rate.time_period;
    }

    cfg->dtcp.rtx.max_time_to_retry = p.dtcp_cfg.rtx_ctrl_cfg.max_time_to_retry;
    cfg->dtcp.rtx.data_rxms_max     = p.dtcp_cfg.rtx_ctrl_cfg.data_rxmsn_max;
    cfg->dtcp.rtx.initial_tr        = p.dtcp_cfg.rtx_ctrl_cfg.initial_tr;
    cfg->dtcp.rtx.max_rtxq_len =
        rib->get_param_value<int>("flow-allocator", "max-rtxq-len");
}

#ifndef RL_USE_QOS_CUBES
/* Any modification to this function must be also reported in the inverse
 * function flowcfg2flowspec(). */
void
LocalFlowAllocator::flowspec2flowcfg(const struct rina_flow_spec *spec,
                                     struct rl_flow_config *cfg) const
{
    bool force_flow_control =
        rib->get_param_value<bool>("flow-allocator", "force-flow-control");
    unsigned initial_a =
        rib->get_param_value<int>("flow-allocator", "initial-a");

    memset(cfg, 0, sizeof(*cfg));

    cfg->max_sdu_gap       = spec->max_sdu_gap;
    cfg->in_order_delivery = spec->in_order_delivery;
    cfg->msg_boundaries    = spec->msg_boundaries;
    cfg->dtcp.bandwidth    = spec->avg_bandwidth;

    if (spec->max_sdu_gap == 0) {
        /* We need retransmission control. */
        cfg->dtcp_present               = 1;
        cfg->in_order_delivery          = 1;
        cfg->dtcp.rtx_control           = 1;
        cfg->dtcp.rtx.max_time_to_retry = 15; /* unused for now */
        cfg->dtcp.rtx.data_rxms_max     = RL_DATA_RXMS_MAX_DFLT;
        cfg->dtcp.rtx.initial_tr =
            rib->get_param_value<int>("flow-allocator", "initial-tr");
        cfg->dtcp.rtx.max_rtxq_len =
            rib->get_param_value<int>("flow-allocator", "max-rtxq-len");
        cfg->dtcp.initial_a = initial_a;
    }

    /* Delay, loss and jitter ignored for now. */
    (void)spec->max_delay;
    (void)spec->max_loss;
    (void)spec->max_jitter;

    if (force_flow_control || spec->max_sdu_gap == 0) {
        /* We enable flow control if forced by policy or if also
         * retransmission control is needed. */
        cfg->dtcp_present      = 1;
        cfg->dtcp.flow_control = 1;
        cfg->dtcp.fc.cfg.w.max_cwq_len =
            rib->get_param_value<int>("flow-allocator", "max-cwq-len");
        cfg->dtcp.fc.cfg.w.initial_credit =
            rib->get_param_value<int>("flow-allocator", "initial-credit");
        cfg->dtcp.fc.fc_type = RLITE_FC_T_WIN;
        cfg->dtcp.initial_a  = initial_a;
    }

    if (spec->avg_bandwidth) {
        cfg->dtcp_present = 1;
    }
}
#endif /* !RL_USE_QOS_CUBES */

/* (1) Initiator FA <-- Initiator application : FA_REQ */
int
LocalFlowAllocator::fa_req(struct rl_kmsg_fa_req *req, rlm_addr_t remote_addr)
{
    std::unique_ptr<CDAPMessage> m;
    FlowRequest freq;
    ConnId conn_id;
    stringstream obj_name;
    string cubename;
    struct rl_flow_config flowcfg;
    string dest_appl = string(req->remote_appl);

    conn_id.qos_id  = 0;
    conn_id.src_cep = req->local_cep;
    conn_id.dst_cep = 0;

    freq.src_app =
        RinaName(req->local_appl); /* req->local_appl may be nullptr */
    freq.dst_app  = RinaName(dest_appl);
    freq.src_port = req->local_port;
    freq.dst_port = 0;
    freq.src_addr = rib->myaddr;
    freq.dst_addr = remote_addr;
    freq.connections.push_back(conn_id);
    freq.cur_conn_idx = 0;
    freq.state        = true;
    freq.uid          = req->uid; /* on initiator side, uid is generated by
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

    flowcfg2policies(&flowcfg, freq.qos, freq.policies);

    freq.flowcfg                 = flowcfg;
    freq.max_create_flow_retries = 3;
    freq.create_flow_retries     = 0;
    freq.hop_cnt                 = 0;

    obj_name << obj_name::flows << "/" << freq.src_addr << "-"
             << req->local_port;

    m = make_unique<CDAPMessage>();
    m->m_create(obj_class::flow, obj_name.str());

    freq.invoke_id = 0; /* invoke_id is actually set in send_to_dst_addr() */
    freq.flags     = RL_FLOWREQ_INITIATOR | RL_FLOWREQ_SEND_DEL;
    flow_reqs[obj_name.str() + string("L")] = freq;

    return rib->send_to_dst_addr(std::move(m), freq.dst_addr, &freq);
}

/* (3) Slave FA <-- Slave application : FA_RESP */
int
LocalFlowAllocator::fa_resp(struct rl_kmsg_fa_resp *resp)
{
    stringstream obj_name;
    string reason;
    std::unique_ptr<CDAPMessage> m;
    int ret;

    /* Lookup the corresponding FlowRequest. */

    auto f = flow_reqs_tmp.find(resp->kevent_id);

    if (f == flow_reqs_tmp.end()) {
        UPE(rib->uipcp,
            "Spurious flow allocation response, no request for kevent_id %u\n",
            resp->kevent_id);
        return -1;
    }

    FlowRequest &freq = f->second;

    /* Update the freq object with the port-id and cep-id allocated by
     * the kernel. */
    freq.dst_port                    = resp->port_id;
    freq.connections.front().dst_cep = resp->cep_id;

    obj_name << obj_name::flows << "/" << freq.src_addr << "-" << freq.src_port;

    if (resp->response) {
        reason = "Application refused the accept the flow request";
    } else {
        /* Move the freq object from the temporary map to the right one. */
        flow_reqs[obj_name.str() + string("R")] = freq;
    }

    m = make_unique<CDAPMessage>();
    m->m_create_r(obj_class::flow, obj_name.str(), 0, resp->response ? -1 : 0,
                  reason);

    ret = rib->send_to_dst_addr(std::move(m), freq.src_addr, &freq);

    flow_reqs_tmp.erase(f);

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

    FlowRequest freq(objbuf, objlen);
    std::string local_appl, remote_appl;
    struct rl_flow_config flowcfg;

    if (freq.connections.size() < 1) {
        std::unique_ptr<CDAPMessage> m;

        UPE(rib->uipcp, "No connections specified on this flow\n");
        m = make_unique<CDAPMessage>();
        m->m_create_r(rm->obj_class, rm->obj_name, 0, -1,
                      "Cannot find DFT entry");

        return rib->send_to_dst_addr(std::move(m), freq.src_addr, &freq);
    }

    /* freq.dst_app is registered with us, let's go ahead. */

    local_appl  = freq.dst_app;
    remote_appl = freq.src_app;
    policies2flowcfg(&flowcfg, freq.qos, freq.policies);

    freq.invoke_id = rm->invoke_id;
    freq.flags     = RL_FLOWREQ_SEND_DEL;
    freq.uid = kevent_id_cnt++; /* on slave side uid is generated by us, and
                                 * it is also used as 'event_id' by the
                                 * kernel */
    flow_reqs_tmp[freq.uid] = freq;

    uipcp_issue_fa_req_arrived(
        rib->uipcp, freq.uid, freq.src_port, freq.connections.front().src_cep,
        freq.src_addr, local_appl.c_str(), remote_appl.c_str(), &flowcfg);

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

    FlowRequest remote_freq(objbuf, objlen);
    auto f = flow_reqs.find(rm->obj_name + string("L"));

    if (f == flow_reqs.end()) {
        UPE(rib->uipcp,
            "M_CREATE_R for '%s' does not match any pending request\n",
            rm->obj_name.c_str());
        return 0;
    }

    FlowRequest &freq = f->second;

    /* Update the local freq object with the remote one. */
    freq.dst_port                    = remote_freq.dst_port;
    freq.connections.front().dst_cep = remote_freq.connections.front().dst_cep;

    return uipcp_issue_fa_resp_arrived(rib->uipcp, freq.src_port, freq.dst_port,
                                       freq.connections.front().dst_cep,
                                       freq.dst_addr, rm->result ? 1 : 0,
                                       &freq.flowcfg);
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
        obj_name_ext << obj_name::flows << "/" << rib->myaddr << "-"
                     << req->local_port_id;
        obj_name = obj_name_ext.str();
        obj_name_ext << "L";
    } else {
        obj_name_ext << obj_name::flows << "/" << req->remote_addr << "-"
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

    /* We were the initiator. */
    assert(!!(f->second.flags & RL_FLOWREQ_INITIATOR) == !!req->initiator);
    remote_addr = req->initiator ? f->second.dst_addr : f->second.src_addr;
    send_del    = (f->second.flags & RL_FLOWREQ_SEND_DEL);
    flow_reqs.erase(f);

    UPD(rib->uipcp, "Removed flow request %s [port %u]\n",
        obj_name_ext.str().c_str(), req->local_port_id);

    if (!send_del) {
        return 0;
    }

    /* We should wait 2 MPL here before notifying the peer. */
    m = make_unique<CDAPMessage>();
    m->m_delete(obj_class::flow, obj_name);

    return rib->send_to_dst_addr(std::move(m), remote_addr, nullptr);
}

int
LocalFlowAllocator::flows_handler_delete(const CDAPMessage *rm)
{
    rl_port_t local_port;
    stringstream decode;
    string objname;
    unsigned addr, port;
    char separator;

    decode << rm->obj_name.substr(obj_name::flows.size() + 1);
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

    if (addr == rib->myaddr) {
        /* We were the initiator. */
        assert(f->second.flags & RL_FLOWREQ_INITIATOR);
    } else {
        /* We were the target. */
        assert(!(f->second.flags & RL_FLOWREQ_INITIATOR));
    }

    local_port = (f->second.flags & RL_FLOWREQ_INITIATOR) ? f->second.src_port
                                                          : f->second.dst_port;

    /* We received a delete request from the peer, so we won't need to send
     * him a delete request. */
    f->second.flags &= ~RL_FLOWREQ_SEND_DEL;

    return uipcp_issue_flow_dealloc(rib->uipcp, local_port, f->second.uid);
}

int
FlowAllocator::rib_handler(const CDAPMessage *rm, NeighFlow *nf,
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
        const FlowRequest &freq = kvf.second;

        ss << "    [" << ((freq.flags & RL_FLOWREQ_INITIATOR) ? "L" : "R")
           << "]"
           << ", Src=" << static_cast<string>(freq.src_app)
           << ", Dst=" << static_cast<string>(freq.dst_app)
           << ", SrcAddr:Port=" << freq.src_addr << ":" << freq.src_port
           << ", DstAddr:Port=" << freq.dst_addr << ":" << freq.dst_port
           << ", Connections: [";
        for (const ConnId &conn : freq.connections) {
            ss << "<SrcCep=" << conn.src_cep << ", DstCep=" << conn.dst_cep
               << ", QosId=" << conn.qos_id << "> ";
        }
        ss << "]" << endl;
    }
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
    available_policies["flow-allocator"].insert(
        PolicyBuilder("local", [](uipcp_rib *rib) {
            rib->fa = make_unique<LocalFlowAllocator>(rib);
        }));
}
