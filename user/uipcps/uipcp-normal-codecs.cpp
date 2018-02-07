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

#include <iostream>
#include <list>
#include <set>
#include <string>
#include <sstream>

#include "rlite/common.h"
#include "rlite/utils.h"
#include "rlite/cpputils.hpp"

#include "uipcp-normal-codecs.hpp"

#include "BaseRIB.pb.h"
#include "Raft.pb.h"

using namespace std;

static int
ser_common(::google::protobuf::MessageLite &gm, char *buf, int size)
{
    if (gm.ByteSize() > size) {
        PE("User buffer too small [%u/%u]\n", gm.ByteSize(), size);
        return -1;
    }

    gm.SerializeToArray(buf, size);

    return gm.ByteSize();
}

RinaName::RinaName(const std::string &apn_, const std::string &api_,
                   const std::string &aen_, const std::string &aei_)
{
    apn = apn_;
    api = api_;
    aen = aen_;
    aei = aei_;
}

RinaName::RinaName(const struct rina_name *name)
{
    apn = name->apn ? string(name->apn) : string();
    api = name->api ? string(name->api) : string();
    aen = name->aen ? string(name->aen) : string();
    aei = name->aei ? string(name->aei) : string();
}

RinaName::RinaName(const string &str)
{
    rina_components_from_string(str, apn, api, aen, aei);
}

RinaName::RinaName(const char *str)
{
    if (str == nullptr) {
        str = "";
    }
    rina_components_from_string(string(str), apn, api, aen, aei);
}

RinaName::operator std::string() const
{
    return rina_string_from_components(apn, api, aen, aei);
}

bool
RinaName::operator==(const RinaName &other) const
{
    return api == other.api && apn == other.apn && aen == other.aen &&
           aei == other.aei;
}

bool
RinaName::operator!=(const RinaName &other) const
{
    return !(*this == other);
}

int
RinaName::rina_name_fill(struct rina_name *rn)
{
    return ::rina_name_fill(rn, apn.c_str(), api.c_str(), aen.c_str(),
                            aei.c_str());
}

static void
gpb2RinaName(RinaName &name, const gpb::APName &gname)
{
    name.apn = gname.ap_name();
    name.api = gname.ap_instance();
    name.aen = gname.ae_name();
    name.aei = gname.ae_instance();
}

static gpb::APName *
RinaName2gpb(const RinaName &name)
{
    gpb::APName *gan = new gpb::APName();

    gan->set_ap_name(name.apn);
    gan->set_ap_instance(name.api);
    gan->set_ae_name(name.aen);
    gan->set_ae_instance(name.aei);

    return gan;
}

EnrollmentInfo::EnrollmentInfo(const char *buf, unsigned int size)
{
    gpb::EnrollmentInfo gm;

    gm.ParseFromArray(buf, size);

    address = gm.address();
#if 0
    start_early = gm.start_early();
#else
    start_early = true;
#endif

    for (int i = 0; i < gm.supp_difs_size(); i++) {
        lower_difs.push_back(gm.supp_difs(i));
    }
}

int
EnrollmentInfo::serialize(char *buf, unsigned int size) const
{
    gpb::EnrollmentInfo gm;

    gm.set_address(address);
    gm.set_start_early(start_early);

    for (const string &dif : lower_difs) {
        gm.add_supp_difs(dif);
    }

    return ser_common(gm, buf, size);
}

static void
gpb2DFTEntry(DFTEntry &entry, const gpb::DFTEntry &gm)
{
    gpb2RinaName(entry.appl_name, gm.appl_name());
    entry.ipcp_name = gm.ipcp_name();
    entry.timestamp = gm.timestamp();
}

static int
DFTEntry2gpb(const DFTEntry &entry, gpb::DFTEntry &gm)
{
    gpb::APName *gan = RinaName2gpb(entry.appl_name);

    if (!gan) {
        PE("Out of memory\n");
        return -1;
    }

    gm.set_allocated_appl_name(gan);
    gm.set_ipcp_name(entry.ipcp_name);
    gm.set_timestamp(entry.timestamp);

    return 0;
}

DFTEntry::DFTEntry(const char *buf, unsigned int size) : local(false)
{
    gpb::DFTEntry gm;

    gm.ParseFromArray(buf, size);

    gpb2DFTEntry(*this, gm);
}

int
DFTEntry::serialize(char *buf, unsigned int size) const
{
    gpb::DFTEntry gm;
    int ret = DFTEntry2gpb(*this, gm);

    if (ret) {
        return ret;
    }

    return ser_common(gm, buf, size);
}

DFTSlice::DFTSlice(const char *buf, unsigned int size)
{
    gpb::DFTSlice gm;

    gm.ParseFromArray(buf, size);

    for (int i = 0; i < gm.entries_size(); i++) {
        entries.emplace_back();
        gpb2DFTEntry(entries.back(), gm.entries(i));
    }
}

int
DFTSlice::serialize(char *buf, unsigned int size) const
{
    gpb::DFTSlice gm;

    for (const DFTEntry &e : entries) {
        gpb::DFTEntry *gentry;
        int ret;

        gentry = gm.add_entries();
        ret    = DFTEntry2gpb(e, *gentry);
        if (ret) {
            return ret;
        }
    }

    return ser_common(gm, buf, size);
}

static void
gpb2NeighborCandidate(NeighborCandidate &cand, const gpb::NeighborCandidate &gm)
{
    cand.apn     = gm.ap_name();
    cand.api     = gm.ap_instance();
    cand.address = gm.address();

    for (int i = 0; i < gm.supp_difs_size(); i++) {
        cand.lower_difs.push_back(gm.supp_difs(i));
    }
}

static int
NeighborCandidate2gpb(const NeighborCandidate &cand, gpb::NeighborCandidate &gm)
{
    gm.set_ap_name(cand.apn);
    gm.set_ap_instance(cand.api);
    gm.set_address(cand.address);

    for (const string &dif : cand.lower_difs) {
        gm.add_supp_difs(dif);
    }

    return 0;
}

NeighborCandidate::NeighborCandidate(const char *buf, unsigned int size)
{
    gpb::NeighborCandidate gm;

    gm.ParseFromArray(buf, size);

    gpb2NeighborCandidate(*this, gm);
}

int
NeighborCandidate::serialize(char *buf, unsigned int size) const
{
    gpb::NeighborCandidate gm;

    NeighborCandidate2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

bool
NeighborCandidate::operator==(const NeighborCandidate &o) const
{
    if (api != o.api || apn != o.apn || address != o.address ||
        lower_difs.size() != o.lower_difs.size()) {
        return false;
    }

    set<string> s1, s2;

    for (const string &lower : lower_difs) {
        s1.insert(lower);
    }
    for (const string &lower : o.lower_difs) {
        s2.insert(lower);
    }

    return s1 == s2;
}

NeighborCandidateList::NeighborCandidateList(const char *buf, unsigned int size)
{
    gpb::NeighborCandidateList gm;

    gm.ParseFromArray(buf, size);

    for (int i = 0; i < gm.neighbors_size(); i++) {
        candidates.emplace_back();
        gpb2NeighborCandidate(candidates.back(), gm.neighbors(i));
    }
}

int
NeighborCandidateList::serialize(char *buf, unsigned int size) const
{
    gpb::NeighborCandidateList gm;

    for (const NeighborCandidate &cand : candidates) {
        gpb::NeighborCandidate *neigh;
        int ret;

        neigh = gm.add_neighbors();
        ret   = NeighborCandidate2gpb(cand, *neigh);
        if (ret) {
            return ret;
        }
    }

    return ser_common(gm, buf, size);
}

static void
gpb2LowerFlow(LowerFlow &lf, const gpb::LowerFlow &gm)
{
    lf.local_node  = gm.name();
    lf.remote_node = gm.neighbor_name();
    lf.cost        = gm.cost();
    lf.seqnum      = gm.sequence_number();
    lf.state       = gm.state();
    lf.age         = gm.age();
}

static int
LowerFlow2gpb(const LowerFlow &lf, gpb::LowerFlow &gm)
{
    gm.set_name(lf.local_node);
    gm.set_neighbor_name(lf.remote_node);
    gm.set_cost(lf.cost);
    gm.set_sequence_number(lf.seqnum);
    gm.set_state(lf.state);
    gm.set_age(lf.age);

    return 0;
}

LowerFlow::LowerFlow(const char *buf, unsigned int size)
{
    gpb::LowerFlow gm;

    gm.ParseFromArray(buf, size);

    gpb2LowerFlow(*this, gm);
}

int
LowerFlow::serialize(char *buf, unsigned int size) const
{
    gpb::LowerFlow gm;

    LowerFlow2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

LowerFlow::operator std::string() const
{
    stringstream ss;

    ss << "(" << local_node << "," << remote_node << ")";

    return ss.str();
}

LowerFlowList::LowerFlowList(const char *buf, unsigned int size)
{
    gpb::LowerFlowList gm;

    gm.ParseFromArray(buf, size);

    for (int i = 0; i < gm.flows_size(); i++) {
        flows.emplace_back();
        gpb2LowerFlow(flows.back(), gm.flows(i));
    }
}

int
LowerFlowList::serialize(char *buf, unsigned int size) const
{
    gpb::LowerFlowList gm;

    for (const LowerFlow &f : flows) {
        gpb::LowerFlow *flow;
        int ret;

        flow = gm.add_flows();
        ret  = LowerFlow2gpb(f, *flow);
        if (ret) {
            return ret;
        }
    }

    return ser_common(gm, buf, size);
}

static void
gpb2Property(Property &p, const gpb::Property &gm)
{
    p.name  = gm.name();
    p.value = gm.value();
}

static int
Property2gpb(const Property &p, gpb::Property &gm)
{
    gm.set_name(p.name);
    gm.set_value(p.value);

    return 0;
}

Property::Property(const char *buf, unsigned int size)
{
    gpb::Property gm;

    gm.ParseFromArray(buf, size);

    gpb2Property(*this, gm);
}

int
Property::serialize(char *buf, unsigned int size) const
{
    gpb::Property gm;

    Property2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2QosSpec(QosSpec &q, const gpb::QosSpec &gm)
{
    q.name                      = gm.name();
    q.qosid                     = gm.qosid();
    q.avg_bw                    = gm.avg_bw();
    q.avg_sdu_rate              = gm.avg_sdu_rate();
    q.peak_bw_duration          = gm.peak_bw_duration();
    q.peak_sdu_bw_duration      = gm.peak_sdu_rate_duration();
    q.undetected_bit_error_rate = gm.undetected_bit_error_rate();
    q.partial_delivery          = gm.partial_delivery();
    q.in_order_delivery         = gm.in_order_delivery();
    q.max_sdu_gap               = gm.max_sdu_gap();
    q.delay                     = gm.delay();
    q.jitter                    = gm.jitter();
    /* missing extra_parameters */
}

static int
QosSpec2gpb(const QosSpec &q, gpb::QosSpec &gm)
{
    gm.set_name(q.name);
    gm.set_qosid(q.qosid);
    gm.set_avg_bw(q.avg_bw);
    gm.set_avg_sdu_rate(q.avg_sdu_rate);
    gm.set_peak_bw_duration(q.peak_bw_duration);
    gm.set_peak_sdu_rate_duration(q.peak_sdu_bw_duration);
    gm.set_undetected_bit_error_rate(q.undetected_bit_error_rate);
    gm.set_partial_delivery(q.partial_delivery);
    gm.set_in_order_delivery(q.in_order_delivery);
    gm.set_max_sdu_gap(q.max_sdu_gap);
    gm.set_delay(q.delay);
    gm.set_jitter(q.jitter);
    /* missing extra_parameters */

    return 0;
}

QosSpec::QosSpec(const char *buf, unsigned int size)
{
    gpb::QosSpec gm;

    gm.ParseFromArray(buf, size);

    gpb2QosSpec(*this, gm);
}

int
QosSpec::serialize(char *buf, unsigned int size) const
{
    gpb::QosSpec gm;

    QosSpec2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2PolicyDescr(PolicyDescr &p, const gpb::PolicyDescr &gm)
{
    p.name      = gm.name();
    p.impl_name = gm.impl_name();
    p.version   = gm.version();

    for (int i = 0; i < gm.parameters_size(); i++) {
        p.parameters.emplace_back();
        gpb2Property(p.parameters.back(), gm.parameters(i));
    }
}

static int
PolicyDescr2gpb(const PolicyDescr &p, gpb::PolicyDescr &gm)
{
    gm.set_name(p.name);
    gm.set_impl_name(p.impl_name);
    gm.set_version(p.version);

    for (const Property &pr : p.parameters) {
        gpb::Property *param;

        param = gm.add_parameters();
        Property2gpb(pr, *param);
    }

    return 0;
}

PolicyDescr::PolicyDescr(const char *buf, unsigned int size)
{
    gpb::PolicyDescr gm;

    gm.ParseFromArray(buf, size);

    gpb2PolicyDescr(*this, gm);
}

int
PolicyDescr::serialize(char *buf, unsigned int size) const
{
    gpb::PolicyDescr gm;

    PolicyDescr2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2WindowBasedFlowCtrlConfig(WindowBasedFlowCtrlConfig &cfg,
                              const gpb::WindowBasedFlowCtrlConfig &gm)
{
    cfg.max_cwq_len    = gm.max_cwq_len();
    cfg.initial_credit = gm.initial_credit();
    gpb2PolicyDescr(cfg.rcvr_flow_ctrl, gm.rcvr_flow_ctrl());
    gpb2PolicyDescr(cfg.tx_ctrl, gm.tx_ctrl());
}

static int
WindowBasedFlowCtrlConfig2gpb(const WindowBasedFlowCtrlConfig &cfg,
                              gpb::WindowBasedFlowCtrlConfig &gm)
{
    gpb::PolicyDescr *p;

    gm.set_max_cwq_len(cfg.max_cwq_len);
    gm.set_initial_credit(cfg.initial_credit);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.rcvr_flow_ctrl, *p);
    gm.set_allocated_rcvr_flow_ctrl(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.tx_ctrl, *p);
    gm.set_allocated_tx_ctrl(p);

    return 0;
}

WindowBasedFlowCtrlConfig::WindowBasedFlowCtrlConfig(const char *buf,
                                                     unsigned int size)
{
    gpb::WindowBasedFlowCtrlConfig gm;

    gm.ParseFromArray(buf, size);

    gpb2WindowBasedFlowCtrlConfig(*this, gm);
}

int
WindowBasedFlowCtrlConfig::serialize(char *buf, unsigned int size) const
{
    gpb::WindowBasedFlowCtrlConfig gm;

    WindowBasedFlowCtrlConfig2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2RateBasedFlowCtrlConfig(RateBasedFlowCtrlConfig &cfg,
                            const gpb::RateBasedFlowCtrlConfig &gm)
{
    cfg.sender_rate = gm.sender_rate();
    cfg.time_period = gm.time_period();
    gpb2PolicyDescr(cfg.no_rate_slow_down, gm.no_rate_slow_down());
    gpb2PolicyDescr(cfg.no_override_default_peak,
                    gm.no_override_default_peak());
    gpb2PolicyDescr(cfg.rate_reduction, gm.rate_reduction());
}

static int
RateBasedFlowCtrlConfig2gpb(const RateBasedFlowCtrlConfig &cfg,
                            gpb::RateBasedFlowCtrlConfig &gm)
{
    gpb::PolicyDescr *p;

    gm.set_sender_rate(cfg.sender_rate);
    gm.set_time_period(cfg.time_period);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.no_rate_slow_down, *p);
    gm.set_allocated_no_rate_slow_down(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.no_override_default_peak, *p);
    gm.set_allocated_no_override_default_peak(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.rate_reduction, *p);
    gm.set_allocated_rate_reduction(p);

    return 0;
}

RateBasedFlowCtrlConfig::RateBasedFlowCtrlConfig(const char *buf,
                                                 unsigned int size)
{
    gpb::RateBasedFlowCtrlConfig gm;

    gm.ParseFromArray(buf, size);

    gpb2RateBasedFlowCtrlConfig(*this, gm);
}

int
RateBasedFlowCtrlConfig::serialize(char *buf, unsigned int size) const
{
    gpb::RateBasedFlowCtrlConfig gm;

    RateBasedFlowCtrlConfig2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2FlowCtrlConfig(FlowCtrlConfig &cfg, const gpb::FlowCtrlConfig &gm)
{
    if (gm.window_based()) {
        cfg.fc_type = RLITE_FC_T_WIN;
    } else if (gm.rate_based()) {
        cfg.fc_type = RLITE_FC_T_RATE;
    }
    gpb2WindowBasedFlowCtrlConfig(cfg.win, gm.window_based_config());
    gpb2RateBasedFlowCtrlConfig(cfg.rate, gm.rate_based_config());
    cfg.sent_bytes_th      = gm.send_bytes_th();
    cfg.sent_bytes_perc_th = gm.sent_bytes_perc_th();
    cfg.sent_buffers_th    = gm.sent_buffers_th();
    cfg.rcv_bytes_th       = gm.rcv_bytes_th();
    cfg.rcv_bytes_perc_th  = gm.rcv_bytes_perc_th();
    cfg.rcv_buffers_th     = gm.rcv_buffers_th();
    gpb2PolicyDescr(cfg.closed_win, gm.closed_win());
    gpb2PolicyDescr(cfg.flow_ctrl_overrun, gm.flow_ctrl_overrun());
    gpb2PolicyDescr(cfg.reconcile_flow_ctrl, gm.reconcile_flow_ctrl());
    gpb2PolicyDescr(cfg.receiving_flow_ctrl, gm.receiving_flow_ctrl());
}

static int
FlowCtrlConfig2gpb(const FlowCtrlConfig &cfg, gpb::FlowCtrlConfig &gm)
{
    gpb::WindowBasedFlowCtrlConfig *w;
    gpb::RateBasedFlowCtrlConfig *r;
    gpb::PolicyDescr *p;

    gm.set_window_based(cfg.fc_type == RLITE_FC_T_WIN);
    gm.set_rate_based(cfg.fc_type == RLITE_FC_T_RATE);

    w = new gpb::WindowBasedFlowCtrlConfig;
    WindowBasedFlowCtrlConfig2gpb(cfg.win, *w);
    gm.set_allocated_window_based_config(w);

    r = new gpb::RateBasedFlowCtrlConfig;
    RateBasedFlowCtrlConfig2gpb(cfg.rate, *r);
    gm.set_allocated_rate_based_config(r);

    gm.set_send_bytes_th(cfg.sent_bytes_th);
    gm.set_sent_bytes_perc_th(cfg.sent_bytes_perc_th);
    gm.set_sent_buffers_th(cfg.sent_buffers_th);
    gm.set_rcv_bytes_th(cfg.rcv_bytes_th);
    gm.set_rcv_bytes_perc_th(cfg.rcv_bytes_perc_th);
    gm.set_rcv_buffers_th(cfg.rcv_buffers_th);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.closed_win, *p);
    gm.set_allocated_closed_win(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.flow_ctrl_overrun, *p);
    gm.set_allocated_flow_ctrl_overrun(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.reconcile_flow_ctrl, *p);
    gm.set_allocated_reconcile_flow_ctrl(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.receiving_flow_ctrl, *p);
    gm.set_allocated_receiving_flow_ctrl(p);

    return 0;
}

FlowCtrlConfig::FlowCtrlConfig(const char *buf, unsigned int size)
{
    gpb::FlowCtrlConfig gm;

    gm.ParseFromArray(buf, size);

    gpb2FlowCtrlConfig(*this, gm);
}

int
FlowCtrlConfig::serialize(char *buf, unsigned int size) const
{
    gpb::FlowCtrlConfig gm;

    FlowCtrlConfig2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2RtxCtrlConfig(RtxCtrlConfig &cfg, const gpb::RtxCtrlConfig &gm)
{
    cfg.max_time_to_retry   = gm.max_time_to_retry();
    cfg.data_rxmsn_max      = gm.data_rxmsn_max();
    cfg.initial_rtx_timeout = gm.initial_rtx_timeout();
    gpb2PolicyDescr(cfg.rtx_timer_expiry, gm.rtx_timer_expiry());
    gpb2PolicyDescr(cfg.sender_ack, gm.sender_ack());
    gpb2PolicyDescr(cfg.receiving_ack_list, gm.receiving_ack_list());
    gpb2PolicyDescr(cfg.rcvr_ack, gm.rcvr_ack());
    gpb2PolicyDescr(cfg.sending_ack, gm.sending_ack());
    gpb2PolicyDescr(cfg.rcvr_ctrl_ack, gm.rcvr_ctrl_ack());
}

static int
RtxCtrlConfig2gpb(const RtxCtrlConfig &cfg, gpb::RtxCtrlConfig &gm)
{
    gpb::PolicyDescr *p;

    gm.set_max_time_to_retry(cfg.max_time_to_retry);
    gm.set_data_rxmsn_max(cfg.data_rxmsn_max);
    gm.set_initial_rtx_timeout(cfg.initial_rtx_timeout);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.rtx_timer_expiry, *p);
    gm.set_allocated_rtx_timer_expiry(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.sender_ack, *p);
    gm.set_allocated_sender_ack(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.receiving_ack_list, *p);
    gm.set_allocated_receiving_ack_list(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.rcvr_ack, *p);
    gm.set_allocated_rcvr_ack(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.sending_ack, *p);
    gm.set_allocated_sending_ack(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.rcvr_ctrl_ack, *p);
    gm.set_allocated_rcvr_ctrl_ack(p);

    return 0;
}

RtxCtrlConfig::RtxCtrlConfig(const char *buf, unsigned int size)
{
    gpb::RtxCtrlConfig gm;

    gm.ParseFromArray(buf, size);

    gpb2RtxCtrlConfig(*this, gm);
}

int
RtxCtrlConfig::serialize(char *buf, unsigned int size) const
{
    gpb::RtxCtrlConfig gm;

    RtxCtrlConfig2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2DtcpConfig(DtcpConfig &cfg, const gpb::DtcpConfig &gm)
{
    cfg.flow_ctrl = gm.flow_ctrl();
    cfg.rtx_ctrl  = gm.rtx_ctrl();
    gpb2FlowCtrlConfig(cfg.flow_ctrl_cfg, gm.flow_ctrl_cfg());
    gpb2RtxCtrlConfig(cfg.rtx_ctrl_cfg, gm.rtx_ctrl_cfg());
    gpb2PolicyDescr(cfg.lost_ctrl_pdu, gm.lost_ctrl_pdu());
    gpb2PolicyDescr(cfg.rtt_estimator, gm.rtt_estimator());
}

static int
DtcpConfig2gpb(const DtcpConfig &cfg, gpb::DtcpConfig &gm)
{
    gpb::PolicyDescr *p;
    gpb::FlowCtrlConfig *f;
    gpb::RtxCtrlConfig *r;

    gm.set_flow_ctrl(cfg.flow_ctrl);
    gm.set_rtx_ctrl(cfg.rtx_ctrl);

    f = new gpb::FlowCtrlConfig;
    FlowCtrlConfig2gpb(cfg.flow_ctrl_cfg, *f);
    gm.set_allocated_flow_ctrl_cfg(f);

    r = new gpb::RtxCtrlConfig;
    RtxCtrlConfig2gpb(cfg.rtx_ctrl_cfg, *r);
    gm.set_allocated_rtx_ctrl_cfg(r);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.lost_ctrl_pdu, *p);
    gm.set_allocated_lost_ctrl_pdu(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.rtt_estimator, *p);
    gm.set_allocated_rtt_estimator(p);

    return 0;
}

DtcpConfig::DtcpConfig(const char *buf, unsigned int size)
{
    gpb::DtcpConfig gm;

    gm.ParseFromArray(buf, size);

    gpb2DtcpConfig(*this, gm);
}

int
DtcpConfig::serialize(char *buf, unsigned int size) const
{
    gpb::DtcpConfig gm;

    DtcpConfig2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2ConnPolicies(ConnPolicies &cfg, const gpb::ConnPolicies &gm)
{
    cfg.dtcp_present        = gm.dtcp_present();
    cfg.seq_num_rollover_th = gm.seq_num_rollover_th();
    cfg.initial_a_timer     = gm.initial_a_timer();
    gpb2DtcpConfig(cfg.dtcp_cfg, gm.dtcp_cfg());
    gpb2PolicyDescr(cfg.rcvr_timer_inact, gm.rcvr_timer_inact());
    gpb2PolicyDescr(cfg.sender_timer_inact, gm.sender_timer_inact());
    gpb2PolicyDescr(cfg.init_seq_num, gm.init_seq_num());
}

static int
ConnPolicies2gpb(const ConnPolicies &cfg, gpb::ConnPolicies &gm)
{
    gpb::PolicyDescr *p;
    gpb::DtcpConfig *d;

    gm.set_dtcp_present(cfg.dtcp_present);
    gm.set_seq_num_rollover_th(cfg.seq_num_rollover_th);
    gm.set_initial_a_timer(cfg.initial_a_timer);

    d = new gpb::DtcpConfig;
    DtcpConfig2gpb(cfg.dtcp_cfg, *d);
    gm.set_allocated_dtcp_cfg(d);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.rcvr_timer_inact, *p);
    gm.set_allocated_rcvr_timer_inact(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.sender_timer_inact, *p);
    gm.set_allocated_sender_timer_inact(p);

    p = new gpb::PolicyDescr;
    PolicyDescr2gpb(cfg.init_seq_num, *p);
    gm.set_allocated_init_seq_num(p);

    return 0;
}

ConnPolicies::ConnPolicies(const char *buf, unsigned int size)
{
    gpb::ConnPolicies gm;

    gm.ParseFromArray(buf, size);

    gpb2ConnPolicies(*this, gm);
}

int
ConnPolicies::serialize(char *buf, unsigned int size) const
{
    gpb::ConnPolicies gm;

    ConnPolicies2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2ConnId(ConnId &id, const gpb::ConnId &gm)
{
    id.qosid   = gm.qosid();
    id.src_cep = gm.src_cep();
    id.dst_cep = gm.dst_cep();
}

static int
ConnId2gpb(const ConnId &id, gpb::ConnId &gm)
{
    gm.set_qosid(id.qosid);
    gm.set_src_cep(id.src_cep);
    gm.set_dst_cep(id.dst_cep);

    return 0;
}

ConnId::ConnId(const char *buf, unsigned int size)
{
    gpb::ConnId gm;

    gm.ParseFromArray(buf, size);

    gpb2ConnId(*this, gm);
}

int
ConnId::serialize(char *buf, unsigned int size) const
{
    gpb::ConnId gm;

    ConnId2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2FlowRequest(FlowRequest &fr, const gpb::FlowRequest &gm)
{
    gpb2RinaName(fr.src_app, gm.src_app());
    gpb2RinaName(fr.dst_app, gm.dst_app());
    fr.src_port = gm.src_port();
    fr.dst_port = gm.dst_port();
    fr.src_addr = gm.src_addr();
    fr.dst_addr = gm.dst_addr();
    for (int i = 0; i < gm.connections_size(); i++) {
        fr.connections.emplace_back();
        gpb2ConnId(fr.connections.back(), gm.connections(i));
    }
    fr.cur_conn_idx = gm.cur_conn_idx();
    fr.state        = gm.state();
    gpb2QosSpec(fr.qos, gm.qos());
    gpb2ConnPolicies(fr.policies, gm.policies());
    fr.access_ctrl             = nullptr;
    fr.max_create_flow_retries = gm.max_create_flow_retries();
    fr.create_flow_retries     = gm.create_flow_retries();
    fr.hop_cnt                 = gm.hop_cnt();
}

static int
FlowRequest2gpb(const FlowRequest &fr, gpb::FlowRequest &gm)
{
    gpb::APName *name;
    gpb::QosSpec *q;
    gpb::ConnPolicies *p;

    name = RinaName2gpb(fr.src_app);
    gm.set_allocated_src_app(name);

    name = RinaName2gpb(fr.dst_app);
    gm.set_allocated_dst_app(name);

    gm.set_src_port(fr.src_port);
    gm.set_dst_port(fr.dst_port);
    gm.set_src_addr(fr.src_addr);
    gm.set_dst_addr(fr.dst_addr);
    for (const ConnId &conn : fr.connections) {
        gpb::ConnId *c = gm.add_connections();

        ConnId2gpb(conn, *c);
    }
    gm.set_cur_conn_idx(fr.cur_conn_idx);
    gm.set_state(fr.state);

    q = new gpb::QosSpec;
    QosSpec2gpb(fr.qos, *q);
    gm.set_allocated_qos(q);

    p = new gpb::ConnPolicies;
    ConnPolicies2gpb(fr.policies, *p);
    gm.set_allocated_policies(p);

    /* access_ctrl not considered --> it will be empty */

    gm.set_max_create_flow_retries(fr.max_create_flow_retries);
    gm.set_create_flow_retries(fr.create_flow_retries);
    gm.set_hop_cnt(fr.hop_cnt);

    return 0;
}

FlowRequest::FlowRequest(const char *buf, unsigned int size)
{
    gpb::FlowRequest gm;

    gm.ParseFromArray(buf, size);

    gpb2FlowRequest(*this, gm);

    flags = 0;
}

int
FlowRequest::serialize(char *buf, unsigned int size) const
{
    gpb::FlowRequest gm;

    FlowRequest2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

AData::AData(const char *buf, unsigned int size)
{
    gpb::AData gm;

    gm.ParseFromArray(buf, size);

    src_addr = gm.src_addr();
    dst_addr = gm.dst_addr();
    cdap     = std::move(
        msg_deser_stateless(gm.cdap_msg().data(), gm.cdap_msg().size()));
}

int
AData::serialize(char *buf, unsigned int size) const
{
    gpb::AData gm;
    char *serbuf = nullptr;
    size_t serlen;
    int ret;

    gm.set_src_addr(src_addr);
    gm.set_dst_addr(dst_addr);
    if (cdap) {
        msg_ser_stateless(cdap.get(), &serbuf, &serlen);
        gm.set_cdap_msg(serbuf, serlen);
    }

    ret = ser_common(gm, buf, size);

    if (serbuf) {
        delete[] serbuf;
    }

    return ret;
}

static void
gpb2AddrAllocRequest(AddrAllocRequest &a, const gpb::AddrAllocRequest &gm)
{
    a.requestor = gm.requestor();
    a.address   = gm.address();
}

static int
AddrAllocRequest2gpb(const AddrAllocRequest &a, gpb::AddrAllocRequest &gm)
{
    gm.set_requestor(a.requestor);
    gm.set_address(a.address);

    return 0;
}

AddrAllocRequest::AddrAllocRequest(const char *buf, unsigned int size)
{
    gpb::AddrAllocRequest gm;

    gm.ParseFromArray(buf, size);

    gpb2AddrAllocRequest(*this, gm);
}

int
AddrAllocRequest::serialize(char *buf, unsigned int size) const
{
    gpb::AddrAllocRequest gm;

    AddrAllocRequest2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

AddrAllocEntries::AddrAllocEntries(const char *buf, unsigned int size)
{
    gpb::AddrAllocEntries gm;

    gm.ParseFromArray(buf, size);

    for (int i = 0; i < gm.entries_size(); i++) {
        entries.emplace_back();
        gpb2AddrAllocRequest(entries.back(), gm.entries(i));
    }
}

int
AddrAllocEntries::serialize(char *buf, unsigned int size) const
{
    gpb::AddrAllocEntries gm;

    for (const AddrAllocRequest &r : entries) {
        gpb::AddrAllocRequest *gr;
        int ret;

        gr  = gm.add_entries();
        ret = AddrAllocRequest2gpb(r, *gr);
        if (ret) {
            return ret;
        }
    }

    return ser_common(gm, buf, size);
}

RaftRequestVote::RaftRequestVote(const char *buf, unsigned int size)
{
    gpb::RaftRequestVote gm;

    gm.ParseFromArray(buf, size);

    term           = gm.term();
    candidate_id   = gm.candidate_id();
    last_log_index = gm.last_log_index();
    last_log_term  = gm.last_log_term();
}

int
RaftRequestVote::serialize(char *buf, unsigned int size) const
{
    gpb::RaftRequestVote gm;

    gm.set_term(term);
    gm.set_candidate_id(candidate_id);
    gm.set_last_log_index(last_log_index);
    gm.set_last_log_term(last_log_term);

    return ser_common(gm, buf, size);
}

RaftRequestVoteResp::RaftRequestVoteResp(const char *buf, unsigned int size)
{
    gpb::RaftRequestVoteResp gm;

    gm.ParseFromArray(buf, size);

    term         = gm.term();
    vote_granted = gm.vote_granted();
}

int
RaftRequestVoteResp::serialize(char *buf, unsigned int size) const
{
    gpb::RaftRequestVoteResp gm;

    gm.set_term(term);
    gm.set_vote_granted(vote_granted);

    return ser_common(gm, buf, size);
}

RaftAppendEntries::RaftAppendEntries(const char *buf, unsigned int size)
{
    gpb::RaftAppendEntries gm;

    gm.ParseFromArray(buf, size);

    term           = gm.term();
    leader_id      = gm.leader_id();
    leader_commit  = gm.leader_commit();
    prev_log_index = gm.prev_log_index();
    prev_log_term  = gm.prev_log_term();

    for (int i = 0; i < gm.entries_size(); i++) {
        size_t bufsize = gm.entries(i).buffer().size();
        auto bufcopy   = std::unique_ptr<char[]>(new char[bufsize]);
        memcpy(bufcopy.get(), gm.entries(i).buffer().data(), bufsize);
        entries.push_back(
            std::make_pair(gm.entries(i).term(), std::move(bufcopy)));
        EntrySize = bufsize;
    }
}

int
RaftAppendEntries::serialize(char *buf, unsigned int size) const
{
    gpb::RaftAppendEntries gm;

    gm.set_term(term);
    gm.set_leader_id(leader_id);
    gm.set_leader_commit(leader_commit);
    gm.set_prev_log_index(prev_log_index);
    gm.set_prev_log_term(prev_log_term);

    assert(EntrySize != 0);
    for (const auto &p : entries) {
        gpb::RaftLogEntry *ge;

        ge = gm.add_entries();
        ge->set_term(p.first);
        ge->set_buffer(p.second.get(), EntrySize);
    }

    return ser_common(gm, buf, size);
}

RaftAppendEntriesResp::RaftAppendEntriesResp(const char *buf, unsigned int size)
{
    gpb::RaftAppendEntriesResp gm;

    gm.ParseFromArray(buf, size);

    term        = gm.term();
    follower_id = gm.follower_id();
    log_index   = gm.log_index();
    success     = gm.success();
}

int
RaftAppendEntriesResp::serialize(char *buf, unsigned int size) const
{
    gpb::RaftAppendEntriesResp gm;

    gm.set_term(term);
    gm.set_follower_id(follower_id);
    gm.set_log_index(log_index);
    gm.set_success(success);

    return ser_common(gm, buf, size);
}
