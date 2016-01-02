#include <sstream>

#include "uipcp-normal.hpp"

using namespace std;


int
uipcp_rib::flow_deallocated(struct rina_kmsg_flow_deallocated *req)
{
    stringstream obj_name;
    map<string, FlowRequest>::iterator f;

    /* Lookup the corresponding FlowRequest. */

    obj_name << obj_name::flows << "/" << ipcp_info()->ipcp_addr
                << "-" << req->local_port_id;

    f = flow_reqs.find(obj_name.str());

    if (f == flow_reqs.end()) {
        obj_name.str(string());
        obj_name << obj_name::flows << "/" << req->remote_addr
            << "-" << req->remote_port_id;

        f = flow_reqs.find(obj_name.str());
    }

    if (f == flow_reqs.end()) {
        PE("Spurious flow allocation response, no object with name %s\n",
            obj_name.str().c_str());
        return -1;
    }

    flow_reqs.erase(f);
    PD("Removed flow request %s\n", obj_name.str().c_str());

    return 0;
}

static void
flowcfg2policies(const struct rina_flow_config *cfg,
                 QosSpec &q,
                 ConnPolicies& p)
{
    q.partial_delivery = cfg->partial_delivery;
    /* req->flowcfg.incomplete_delivery ? */
    q.in_order_delivery = cfg->in_order_delivery;
    q.max_sdu_gap = cfg->max_sdu_gap;

    p.dtcp_present = cfg->dtcp_present;
    p.initial_a_timer = cfg->dtcp.initial_a; /* mismatch... */

    p.dtcp_cfg.flow_ctrl = cfg->dtcp.flow_control;
    p.dtcp_cfg.rtx_ctrl = cfg->dtcp.rtx_control;

    p.dtcp_cfg.flow_ctrl_cfg.fc_type = cfg->dtcp.fc.fc_type;
    if (cfg->dtcp.fc.fc_type == RINA_FC_T_WIN) {
        p.dtcp_cfg.flow_ctrl_cfg.win.max_cwq_len =
                        cfg->dtcp.fc.cfg.w.max_cwq_len;
        p.dtcp_cfg.flow_ctrl_cfg.win.initial_credit =
                        cfg->dtcp.fc.cfg.w.initial_credit;

    } else if (cfg->dtcp.fc.fc_type == RINA_FC_T_RATE) {
        p.dtcp_cfg.flow_ctrl_cfg.rate.sending_rate =
                        cfg->dtcp.fc.cfg.r.sending_rate;
        p.dtcp_cfg.flow_ctrl_cfg.rate.time_period =
                        cfg->dtcp.fc.cfg.r.time_period;
    }

    p.dtcp_cfg.rtx_ctrl_cfg.max_time_to_retry =
                        cfg->dtcp.rtx.max_time_to_retry;
    p.dtcp_cfg.rtx_ctrl_cfg.data_rxmsn_max =
                        cfg->dtcp.rtx.data_rxms_max; /* mismatch... */
    p.dtcp_cfg.rtx_ctrl_cfg.initial_tr =
                        cfg->dtcp.rtx.initial_tr;
}

static void
policies2flowcfg(struct rina_flow_config *cfg,
                 const QosSpec &q,
                 const ConnPolicies& p)
{
    cfg->partial_delivery = q.partial_delivery;
     cfg->in_order_delivery = q.in_order_delivery;
    cfg->max_sdu_gap = q.max_sdu_gap;

    cfg->dtcp_present = p.dtcp_present;
    cfg->dtcp.initial_a = p.initial_a_timer;

    cfg->dtcp.flow_control = p.dtcp_cfg.flow_ctrl;
    cfg->dtcp.rtx_control = p.dtcp_cfg.rtx_ctrl;

    cfg->dtcp.fc.fc_type = p.dtcp_cfg.flow_ctrl_cfg.fc_type;
    if (cfg->dtcp.fc.fc_type == RINA_FC_T_WIN) {
        cfg->dtcp.fc.cfg.w.max_cwq_len =
                        p.dtcp_cfg.flow_ctrl_cfg.win.max_cwq_len;
        cfg->dtcp.fc.cfg.w.initial_credit =
                        p.dtcp_cfg.flow_ctrl_cfg.win.initial_credit;

    } else if (cfg->dtcp.fc.fc_type == RINA_FC_T_RATE) {
        cfg->dtcp.fc.cfg.r.sending_rate =
                        p.dtcp_cfg.flow_ctrl_cfg.rate.sending_rate;
        cfg->dtcp.fc.cfg.r.time_period =
                        p.dtcp_cfg.flow_ctrl_cfg.rate.time_period;
    }

    cfg->dtcp.rtx.max_time_to_retry =
                        p.dtcp_cfg.rtx_ctrl_cfg.max_time_to_retry;
    cfg->dtcp.rtx.data_rxms_max =
                        p.dtcp_cfg.rtx_ctrl_cfg.data_rxmsn_max;
    cfg->dtcp.rtx.initial_tr = p.dtcp_cfg.rtx_ctrl_cfg.initial_tr;
}

/* (1) Initiator FA <-- Initiator application : FA_REQ */
int
uipcp_rib::fa_req(struct rina_kmsg_fa_req *req)
{
    RinaName dest_appl(&req->remote_appl);
    uint64_t remote_addr = dft_lookup(dest_appl);
    struct rlite_ipcp *ipcp;
    CDAPMessage m;
    FlowRequest freq;
    ConnId conn_id;
    stringstream obj_name;
    string cubename;
    struct rina_flow_config flowcfg;
    map<string, struct rina_flow_config>::iterator qcmi;

    if (!remote_addr) {
        /* Return a negative flow allocation response immediately. */
        PI("No DFT matching entry for destination %s\n",
                static_cast<string>(dest_appl).c_str());

        return uipcp_issue_fa_resp_arrived(uipcp, req->local_port,
                                     0 /* don't care */,
                                     0 /* don't care */,
                                     0 /* don't care */,
                                     1, NULL);
    }

    ipcp = ipcp_info();

    conn_id.qos_id = 0;
    conn_id.src_cep = req->local_cep;
    conn_id.dst_cep = 0;

    freq.src_app = RinaName(&req->local_appl);
    freq.dst_app = dest_appl;
    freq.src_port = req->local_port;
    freq.dst_port = 0;
    freq.src_addr = ipcp->ipcp_addr;
    freq.dst_addr = remote_addr;
    freq.connections.push_back(conn_id);
    freq.cur_conn_idx = 0;
    freq.state = true;

    /* Translate the flow specification into a QoSCube.
     * For now this is accomplished by just specifying the
     * QoSCube name in the flow specification. */
    cubename = string(req->flowspec.cubename);
    qcmi = qos_cubes.find(cubename);
    if (qcmi == qos_cubes.end()) {
        PI("Cannot find QoSCube '%s': Using default flow configuration\n",
           cubename.c_str());
        rlite_flow_cfg_default(&flowcfg);
    } else {
        flowcfg = qcmi->second;
        PI("QoSCube '%s' selected\n", qcmi->first.c_str());
    }

    flowcfg2policies(&flowcfg, freq.qos, freq.policies);

    freq.flowcfg = flowcfg;
    freq.max_create_flow_retries = 3;
    freq.create_flow_retries = 0;
    freq.hop_cnt = 0;

    obj_name << obj_name::flows << "/" << freq.src_addr
                << "-" << req->local_port;

    m.m_create(gpb::F_NO_FLAGS, obj_class::flow, obj_name.str(),
               0, 0, string());

    freq.invoke_id = 0;  /* invoke_id is actually set in send_to_dst_addr() */
    flow_reqs[obj_name.str()] = freq;

    return send_to_dst_addr(m, freq.dst_addr, freq);
}

/* (3) Slave FA <-- Slave application : FA_RESP */
int
uipcp_rib::fa_resp(struct rina_kmsg_fa_resp *resp)
{
    stringstream obj_name;
    map<unsigned int, FlowRequest>::iterator f;
    string reason;
    CDAPMessage m;
    int ret;

    /* Lookup the corresponding FlowRequest. */

    f = flow_reqs_tmp.find(resp->kevent_id);
    if (f == flow_reqs_tmp.end()) {
        PE("Spurious flow allocation response, no request for kevent_id %u\n",
           resp->kevent_id);
        return -1;
    }

    FlowRequest& freq = f->second;

    if (resp->response) {
        reason = "Application refused the accept the flow request";
    } else {
        /* Update the freq object with the port-id and cep-id allocated by
         * the kernel. */
        freq.dst_port = resp->port_id;
        freq.connections.front().dst_cep = resp->cep_id;

        /* Move the freq object from the temporary map to the right one. */
        obj_name << obj_name::flows << "/" << freq.src_addr
                 << "-" << freq.src_port;
        flow_reqs[obj_name.str()] = freq;
    }

    m.m_create_r(gpb::F_NO_FLAGS, obj_class::flow, obj_name.str(), 0,
                 resp->response ? -1 : 0, reason);

    ret = send_to_dst_addr(m, freq.src_addr, freq);

    flow_reqs_tmp.erase(f);

    return ret;
}

/* (2) Slave FA <-- Initiator FA : M_CREATE */
int
uipcp_rib::flows_handler_create(const CDAPMessage *rm, Neighbor *neigh)
{
    const char *objbuf;
    size_t objlen;

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_CREATE does not contain a nested message\n");
        return 0;
    }

    FlowRequest freq(objbuf, objlen);
    struct rina_name local_appl, remote_appl;
    struct rina_flow_config flowcfg;
    uint64_t dft_next_hop;

    dft_next_hop = dft_lookup(freq.dst_app);
    if (!dft_next_hop) {
        /* We don't know how where this application is registered,
         * reject the request. */
        CDAPMessage m;

        PI("Cannot find DFT entry for %s\n",
           static_cast<string>(freq.dst_app).c_str());

        m.m_create_r(gpb::F_NO_FLAGS, rm->obj_class, rm->obj_name, 0,
                     -1, "Cannot find DFT entry");

        return send_to_dst_addr(m, freq.src_addr, freq);
    }

    if (dft_next_hop != ipcp_info()->ipcp_addr) {
        /* freq.dst_app is not registered with us, we have
         * to forward the request. TODO */
        CDAPMessage m;

        PE("Flow request forwarding not supported\n");
        m.m_create_r(gpb::F_NO_FLAGS, rm->obj_class, rm->obj_name, 0,
                     -1, "Flow request forwarding not supported");

        return send_to_dst_addr(m, freq.src_addr, freq);
    }

    if (freq.connections.size() < 1) {
        CDAPMessage m;

        PE("No connections specified on this flow\n");
        m.m_create_r(gpb::F_NO_FLAGS, rm->obj_class, rm->obj_name, 0,
                     -1, "Cannot find DFT entry");

        return send_to_dst_addr(m, freq.src_addr, freq);
    }

    /* freq.dst_app is registered with us, let's go ahead. */

    freq.dst_app.rina_name_fill(&local_appl);
    freq.src_app.rina_name_fill(&remote_appl);
    policies2flowcfg(&flowcfg, freq.qos, freq.policies);

    uipcp_issue_fa_req_arrived(uipcp, kevent_id_cnt, freq.src_port,
                               freq.connections.front().src_cep,
                               freq.src_addr, &local_appl, &remote_appl,
                               &flowcfg);

    rina_name_free(&local_appl);
    rina_name_free(&remote_appl);

    freq.invoke_id = rm->invoke_id;
    flow_reqs_tmp[kevent_id_cnt] = freq;

    kevent_id_cnt++;

    return 0;
}

/* (4) Initiator FA <-- Slave FA : M_CREATE_R */
int
uipcp_rib::flows_handler_create_r(const CDAPMessage *rm, Neighbor *neigh)
{
    const char *objbuf;
    size_t objlen;

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_CREATE_R does not contain a nested message\n");
        return 0;
    }

    FlowRequest remote_freq(objbuf, objlen);
    map<string, FlowRequest>::iterator f = flow_reqs.find(rm->obj_name);

    if (f == flow_reqs.end()) {
        PE("M_CREATE_R for '%s' does not match any pending request\n",
                rm->obj_name.c_str());
        return 0;
    }

    FlowRequest& freq = f->second;

    /* Update the local freq object with the remote one. */
    freq.dst_port = remote_freq.dst_port;
    freq.connections.front().dst_cep = remote_freq.connections.front().dst_cep;

    return uipcp_issue_fa_resp_arrived(uipcp, freq.src_port, freq.dst_port,
                                       freq.connections.front().dst_cep,
                                       freq.dst_addr, rm->result,
                                       &freq.flowcfg);
}

int
uipcp_rib::flows_handler(const CDAPMessage *rm, Neighbor *neigh)
{
    switch (rm->op_code) {
        case gpb::M_CREATE:
            return flows_handler_create(rm, neigh);

        case gpb::M_CREATE_R:
            return flows_handler_create_r(rm, neigh);

        case gpb::M_DELETE:
        case gpb::M_DELETE_R:
            PE("NOT SUPPORTED YET");
            assert(0);
            break;

        default:
            PE("M_CREATE, M_CREATE_R, M_DELETE or M_DELETE_R expected\n");
            break;
    }

    return 0;
}

