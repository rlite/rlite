#include <iostream>
#include <list>
#include <string>
#include <sstream>

#include "rlite/common.h"
#include "rlite/utils.h"

#include "uipcp-normal-codecs.hpp"

#include "EnrollmentInformationMessage.pb.h"
#include "ApplicationProcessNamingInfoMessage.pb.h"
#include "DirectoryForwardingTableEntryArrayMessage.pb.h"
#include "DirectoryForwardingTableEntryMessage.pb.h"
#include "NeighborMessage.pb.h"
#include "NeighborArrayMessage.pb.h"
#include "FlowStateMessage.pb.h"
#include "FlowStateGroupMessage.pb.h"
#include "CommonMessages.pb.h"
#include "QoSSpecification.pb.h"
#include "PolicyDescriptorMessage.pb.h"
#include "ConnectionPoliciesMessage.pb.h"
#include "FlowMessage.pb.h"

using namespace std;


static int
ser_common(::google::protobuf::MessageLite &gm, char *buf,
           int size)
{
    if (gm.ByteSize() > size) {
        PE("User buffer too small [%u/%u]\n",
                gm.ByteSize(), size);
        return -1;
    }

    gm.SerializeToArray(buf, size);

    return gm.ByteSize();
}

RinaName::RinaName(const std::string& apn_,
                   const std::string& api_,
                   const std::string& aen_,
                   const std::string& aei_)
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

RinaName::operator std::string() const
{
    return apn + '/' + api + '/' + aen + '/' + aei;
}

bool RinaName::operator==(const RinaName& other) const
{
    return api == other.api && apn == other.apn &&
            aen == other.aen && aei == other.aei;
}

bool RinaName::operator!=(const RinaName& other) const
{
    return !(*this == other);
}

int
RinaName::rina_name_fill(struct rina_name *rn)
{
    return ::rina_name_fill(rn, apn.c_str(), api.c_str(),
                            aen.c_str(), aei.c_str());
}

static void
gpb2RinaName(RinaName &name, const gpb::applicationProcessNamingInfo_t& gname)
{
    name.apn = gname.applicationprocessname();
    name.api = gname.applicationprocessinstance();
    name.aen = gname.applicationentityname();
    name.aei = gname.applicationentityinstance();
}

static gpb::applicationProcessNamingInfo_t *
RinaName2gpb(const RinaName &name)
{
    gpb::applicationProcessNamingInfo_t *gan =
        new gpb::applicationProcessNamingInfo_t();

    gan->set_applicationprocessname(name.apn);
    gan->set_applicationprocessinstance(name.api);
    gan->set_applicationentityname(name.aen);
    gan->set_applicationentityinstance(name.aei);

    return gan;
}

EnrollmentInfo::EnrollmentInfo(const char *buf, unsigned int size)
{
    gpb::enrollmentInformation_t gm;

    gm.ParseFromArray(buf, size);

    address = gm.address();
#if 0
    start_early = gm.startearly();
#else
    start_early = true;
#endif

    for (int i = 0; i < gm.supportingdifs_size(); i++) {
        lower_difs.push_back(gm.supportingdifs(i));
    }
}

int
EnrollmentInfo::serialize(char *buf, unsigned int size) const
{
    gpb::enrollmentInformation_t gm;

    gm.set_address(address);
    gm.set_startearly(start_early);

    for (list<string>::const_iterator dif = lower_difs.begin();
                            dif != lower_difs.end(); dif++) {
        gm.add_supportingdifs(*dif);
    }

    return ser_common(gm, buf, size);
}

static void
gpb2DFTEntry(DFTEntry &entry, const gpb::directoryForwardingTableEntry_t &gm)
{
    gpb2RinaName(entry.appl_name, gm.applicationname());
    entry.address = gm.ipcprocesssynonym();
    entry.timestamp = gm.timestamp();
}

static int
DFTEntry2gpb(const DFTEntry &entry, gpb::directoryForwardingTableEntry_t &gm)
{
    gpb::applicationProcessNamingInfo_t *gan =
        RinaName2gpb(entry.appl_name);

    if (!gan) {
        PE("Out of memory\n");
        return -1;
    }

    gm.set_allocated_applicationname(gan);
    gm.set_ipcprocesssynonym(entry.address);
    gm.set_timestamp(entry.timestamp);

    return 0;
}

DFTEntry::DFTEntry(const char *buf, unsigned int size) : local(false)
{
    gpb::directoryForwardingTableEntry_t gm;

    gm.ParseFromArray(buf, size);

    gpb2DFTEntry(*this, gm);
}

int
DFTEntry::serialize(char *buf, unsigned int size) const
{
    gpb::directoryForwardingTableEntry_t gm;
    int ret = DFTEntry2gpb(*this, gm);

    if (ret) {
        return ret;
    }

    return ser_common(gm, buf, size);
}

DFTSlice::DFTSlice(const char *buf, unsigned int size)
{
    gpb::directoryForwardingTableEntrySet_t gm;

    gm.ParseFromArray(buf, size);

    for (int i = 0; i < gm.directoryforwardingtableentry_size(); i++) {
        entries.push_back(DFTEntry());
        gpb2DFTEntry(entries.back(), gm.directoryforwardingtableentry(i));
    }
}

int
DFTSlice::serialize(char *buf, unsigned int size) const
{
    gpb::directoryForwardingTableEntrySet_t gm;

    for (list<DFTEntry>::const_iterator e = entries.begin();
                    e != entries.end(); e++) {
        gpb::directoryForwardingTableEntry_t *gentry;
        int ret;

        gentry = gm.add_directoryforwardingtableentry();
        ret = DFTEntry2gpb(*e, *gentry);
        if (ret) {
            return ret;
        }
    }

    return ser_common(gm, buf, size);
}

static void
gpb2NeighborCandidate(NeighborCandidate &cand, const gpb::neighbor_t &gm)
{
    cand.apn = gm.applicationprocessname();
    cand.api = gm.applicationprocessinstance();
    cand.address = gm.address();

    for (int i = 0; i < gm.supportingdifs_size(); i++) {
        cand.lower_difs.push_back(gm.supportingdifs(i));
    }
}

static int
NeighborCandidate2gpb(const NeighborCandidate &cand, gpb::neighbor_t &gm)
{
    gm.set_applicationprocessname(cand.apn);
    gm.set_applicationprocessinstance(cand.api);
    gm.set_address(cand.address);

    for (list<string>::const_iterator dif = cand.lower_difs.begin();
                            dif != cand.lower_difs.end(); dif++) {
        gm.add_supportingdifs(*dif);
    }

    return 0;
}

NeighborCandidate::NeighborCandidate(const char *buf, unsigned int size)
{
    gpb::neighbor_t gm;

    gm.ParseFromArray(buf, size);

    gpb2NeighborCandidate(*this, gm);
}

int
NeighborCandidate::serialize(char *buf, unsigned int size) const
{
    gpb::neighbor_t gm;

    NeighborCandidate2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

NeighborCandidateList::NeighborCandidateList(const char *buf, unsigned int size)
{
    gpb::neighbors_t gm;

    gm.ParseFromArray(buf, size);

    for (int i = 0; i < gm.neighbor_size(); i++) {
        candidates.push_back(NeighborCandidate());
        gpb2NeighborCandidate(candidates.back(), gm.neighbor(i));
    }
}

int
NeighborCandidateList::serialize(char *buf, unsigned int size) const
{
    gpb::neighbors_t gm;

    for (list<NeighborCandidate>::const_iterator c = candidates.begin();
                    c != candidates.end(); c++) {
        gpb::neighbor_t *neigh;
        int ret;

        neigh = gm.add_neighbor();
        ret = NeighborCandidate2gpb(*c, *neigh);
        if (ret) {
            return ret;
        }
    }

    return ser_common(gm, buf, size);
}

static void
gpb2LowerFlow(LowerFlow& cand, const gpb::flowStateObject_t &gm)
{
    cand.local_addr = gm.address();
    cand.remote_addr = gm.neighbor_address();
    cand.cost = gm.cost();
    cand.seqnum = gm.sequence_number();
    cand.state = gm.state();
    cand.age = gm.age();
}

static int
LowerFlow2gpb(const LowerFlow& cand, gpb::flowStateObject_t &gm)
{
    gm.set_address(cand.local_addr);
    gm.set_neighbor_address(cand.remote_addr);
    gm.set_cost(cand.cost);
    gm.set_sequence_number(cand.seqnum);
    gm.set_state(cand.state);
    gm.set_age(cand.age);

    return 0;
}

LowerFlow::LowerFlow(const char *buf, unsigned int size)
{
    gpb::flowStateObject_t gm;

    gm.ParseFromArray(buf, size);

    gpb2LowerFlow(*this, gm);
}

int
LowerFlow::serialize(char *buf, unsigned int size) const
{
    gpb::flowStateObject_t gm;

    LowerFlow2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

LowerFlow::operator std::string() const
{
    stringstream ss;

    ss << local_addr << "-" << remote_addr;

    return ss.str();
}

LowerFlowList::LowerFlowList(const char *buf, unsigned int size)
{
    gpb::flowStateObjectGroup_t gm;

    gm.ParseFromArray(buf, size);

    for (int i = 0; i < gm.flow_state_objects_size(); i++) {
        flows.push_back(LowerFlow());
        gpb2LowerFlow(flows.back(), gm.flow_state_objects(i));
    }
}

int
LowerFlowList::serialize(char *buf, unsigned int size) const
{
    gpb::flowStateObjectGroup_t gm;

    for (list<LowerFlow>::const_iterator f = flows.begin();
                    f != flows.end(); f++) {
        gpb::flowStateObject_t *flow;
        int ret;

        flow = gm.add_flow_state_objects();
        ret = LowerFlow2gpb(*f, *flow);
        if (ret) {
            return ret;
        }
    }

    return ser_common(gm, buf, size);
}

static void
gpb2Property(Property& p, const gpb::property_t &gm)
{
    p.name = gm.name();
    p.value = gm.value();
}

static int
Property2gpb(const Property& p, gpb::property_t &gm)
{
    gm.set_name(p.name);
    gm.set_value(p.value);

    return 0;
}

Property::Property(const char *buf, unsigned int size)
{
    gpb::property_t gm;

    gm.ParseFromArray(buf, size);

    gpb2Property(*this, gm);
}

int
Property::serialize(char *buf, unsigned int size) const
{
    gpb::property_t gm;

    Property2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2QosSpec(QosSpec& q, const gpb::qosSpecification_t &gm)
{
    q.name = gm.name();
    q.qos_id = gm.qosid();
    q.avg_bw = gm.averagebandwidth();
    q.avg_sdu_bw = gm.averagesdubandwidth();
    q.peak_bw_duration = gm.peakbandwidthduration();
    q.peak_sdu_bw_duration = gm.peaksdubandwidthduration();
    q.undetected_bit_error_rate = gm.undetectedbiterrorrate();
    q.partial_delivery = gm.partialdelivery();
    q.in_order_delivery = gm.order();
    q.max_sdu_gap = gm.maxallowablegapsdu();
    q.delay = gm.delay();
    q.jitter = gm.jitter();
    /* missing extra_parameters */
}

static int
QosSpec2gpb(const QosSpec& q, gpb::qosSpecification_t &gm)
{
    gm.set_name(q.name);
    gm.set_qosid(q.qos_id);
    gm.set_averagebandwidth(q.avg_bw);
    gm.set_averagesdubandwidth(q.avg_sdu_bw);
    gm.set_peakbandwidthduration(q.peak_bw_duration);
    gm.set_peaksdubandwidthduration(q.peak_sdu_bw_duration);
    gm.set_undetectedbiterrorrate(q.undetected_bit_error_rate);
    gm.set_partialdelivery(q.partial_delivery);
    gm.set_order(q.in_order_delivery);
    gm.set_maxallowablegapsdu(q.max_sdu_gap);
    gm.set_delay(q.delay);
    gm.set_jitter(q.jitter);
    /* missing extra_parameters */

    return 0;
}

QosSpec::QosSpec(const char *buf, unsigned int size)
{
    gpb::qosSpecification_t gm;

    gm.ParseFromArray(buf, size);

    gpb2QosSpec(*this, gm);
}

int
QosSpec::serialize(char *buf, unsigned int size) const
{
    gpb::qosSpecification_t gm;

    QosSpec2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2PolicyDescr(PolicyDescr& p, const gpb::policyDescriptor_t &gm)
{
    p.name = gm.policyname();
    p.impl_name = gm.policyimplname();
    p.version = gm.version();

    for (int i = 0; i < gm.policyparameters_size(); i++) {
        p.parameters.push_back(Property());
        gpb2Property(p.parameters.back(), gm.policyparameters(i));
    }
}

static int
PolicyDescr2gpb(const PolicyDescr& p, gpb::policyDescriptor_t &gm)
{
    gm.set_policyname(p.name);
    gm.set_policyimplname(p.impl_name);
    gm.set_version(p.version);

    for (list<Property>::const_iterator pr = p.parameters.begin();
                            pr != p.parameters.end(); pr++) {
        gpb::property_t *param;

        param = gm.add_policyparameters();
        Property2gpb(*pr, *param);
    }

    return 0;
}

PolicyDescr::PolicyDescr(const char *buf, unsigned int size)
{
    gpb::policyDescriptor_t gm;

    gm.ParseFromArray(buf, size);

    gpb2PolicyDescr(*this, gm);
}

int
PolicyDescr::serialize(char *buf, unsigned int size) const
{
    gpb::policyDescriptor_t gm;

    PolicyDescr2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2WindowBasedFlowCtrlConfig(WindowBasedFlowCtrlConfig& cfg,
                              const gpb::dtcpWindowBasedFlowControlConfig_t &gm)
{
    cfg.max_cwq_len = gm.maxclosedwindowqueuelength();
    cfg.initial_credit = gm.initialcredit();
    gpb2PolicyDescr(cfg.rcvr_flow_ctrl, gm.rcvrflowcontrolpolicy());
    gpb2PolicyDescr(cfg.tx_ctrl, gm.txcontrolpolicy());
}

static int
WindowBasedFlowCtrlConfig2gpb(const WindowBasedFlowCtrlConfig& cfg,
                              gpb::dtcpWindowBasedFlowControlConfig_t &gm)
{
    gpb::policyDescriptor_t *p;

    gm.set_maxclosedwindowqueuelength(cfg.max_cwq_len);
    gm.set_initialcredit(cfg.initial_credit);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.rcvr_flow_ctrl, *p);
    gm.set_allocated_rcvrflowcontrolpolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.tx_ctrl, *p);
    gm.set_allocated_txcontrolpolicy(p);

    return 0;
}

WindowBasedFlowCtrlConfig::WindowBasedFlowCtrlConfig(const char *buf, unsigned int size)
{
    gpb::dtcpWindowBasedFlowControlConfig_t gm;

    gm.ParseFromArray(buf, size);

    gpb2WindowBasedFlowCtrlConfig(*this, gm);
}

int
WindowBasedFlowCtrlConfig::serialize(char *buf, unsigned int size) const
{
    gpb::dtcpWindowBasedFlowControlConfig_t gm;

    WindowBasedFlowCtrlConfig2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2RateBasedFlowCtrlConfig(RateBasedFlowCtrlConfig& cfg,
                            const gpb::dtcpRateBasedFlowControlConfig_t &gm)
{
    cfg.sending_rate = gm.sendingrate();
    cfg.time_period = gm.timeperiod();
    gpb2PolicyDescr(cfg.no_rate_slow_down, gm.norateslowdownpolicy());
    gpb2PolicyDescr(cfg.no_override_default_peak, gm.nooverridedefaultpeakpolicy());
    gpb2PolicyDescr(cfg.rate_reduction, gm.ratereductionpolicy());
}

static int
RateBasedFlowCtrlConfig2gpb(const RateBasedFlowCtrlConfig& cfg,
                            gpb::dtcpRateBasedFlowControlConfig_t &gm)
{
    gpb::policyDescriptor_t *p;

    gm.set_sendingrate(cfg.sending_rate);
    gm.set_timeperiod(cfg.time_period);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.no_rate_slow_down, *p);
    gm.set_allocated_norateslowdownpolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.no_override_default_peak, *p);
    gm.set_allocated_nooverridedefaultpeakpolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.rate_reduction, *p);
    gm.set_allocated_ratereductionpolicy(p);

    return 0;
}

RateBasedFlowCtrlConfig::RateBasedFlowCtrlConfig(const char *buf, unsigned int size)
{
    gpb::dtcpRateBasedFlowControlConfig_t gm;

    gm.ParseFromArray(buf, size);

    gpb2RateBasedFlowCtrlConfig(*this, gm);
}

int
RateBasedFlowCtrlConfig::serialize(char *buf, unsigned int size) const
{
    gpb::dtcpRateBasedFlowControlConfig_t gm;

    RateBasedFlowCtrlConfig2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2FlowCtrlConfig(FlowCtrlConfig& cfg,
                   const gpb::dtcpFlowControlConfig_t &gm)
{
    if (gm.windowbased()) {
        cfg.fc_type = RLITE_FC_T_WIN;
    } else if (gm.ratebased()) {
        cfg.fc_type = RLITE_FC_T_RATE;
    }
    gpb2WindowBasedFlowCtrlConfig(cfg.win, gm.windowbasedconfig());
    gpb2RateBasedFlowCtrlConfig(cfg.rate, gm.ratebasedconfig());
    cfg.sent_bytes_th = gm.sentbytesthreshold();
    cfg.sent_bytes_perc_th = gm.sentbytespercentthreshold();
    cfg.sent_buffer_th = gm.sentbuffersthreshold();
    cfg.rcv_bytes_th = gm.rcvbytesthreshold();
    cfg.rcv_bytes_perc_th = gm.rcvbytespercentthreshold();
    cfg.rcv_buffers_th = gm.rcvbuffersthreshold();
    gpb2PolicyDescr(cfg.closed_win, gm.closedwindowpolicy());
    gpb2PolicyDescr(cfg.flow_ctrl_overrun, gm.flowcontroloverrunpolicy());
    gpb2PolicyDescr(cfg.reconcile_flow_ctrl, gm.reconcileflowcontrolpolicy());
    gpb2PolicyDescr(cfg.receiving_flow_ctrl, gm.receivingflowcontrolpolicy());
}

static int
FlowCtrlConfig2gpb(const FlowCtrlConfig& cfg,
                   gpb::dtcpFlowControlConfig_t &gm)
{
    gpb::dtcpWindowBasedFlowControlConfig_t *w;
    gpb::dtcpRateBasedFlowControlConfig_t *r;
    gpb::policyDescriptor_t *p;

    gm.set_windowbased(cfg.fc_type == RLITE_FC_T_WIN);
    gm.set_ratebased(cfg.fc_type == RLITE_FC_T_RATE);

    w = new gpb::dtcpWindowBasedFlowControlConfig_t;
    WindowBasedFlowCtrlConfig2gpb(cfg.win, *w);
    gm.set_allocated_windowbasedconfig(w);

    r = new gpb::dtcpRateBasedFlowControlConfig_t;
    RateBasedFlowCtrlConfig2gpb(cfg.rate, *r);
    gm.set_allocated_ratebasedconfig(r);

    gm.set_sentbytesthreshold(cfg.sent_bytes_th);
    gm.set_sentbytespercentthreshold(cfg.sent_bytes_perc_th);
    gm.set_sentbuffersthreshold(cfg.sent_buffer_th);
    gm.set_rcvbytesthreshold(cfg.rcv_bytes_th);
    gm.set_rcvbytespercentthreshold(cfg.rcv_bytes_perc_th);
    gm.set_rcvbuffersthreshold(cfg.rcv_buffers_th);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.closed_win, *p);
    gm.set_allocated_closedwindowpolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.flow_ctrl_overrun, *p);
    gm.set_allocated_flowcontroloverrunpolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.reconcile_flow_ctrl, *p);
    gm.set_allocated_reconcileflowcontrolpolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.receiving_flow_ctrl, *p);
    gm.set_allocated_receivingflowcontrolpolicy(p);

    return 0;
}

FlowCtrlConfig::FlowCtrlConfig(const char *buf, unsigned int size)
{
    gpb::dtcpFlowControlConfig_t gm;

    gm.ParseFromArray(buf, size);

    gpb2FlowCtrlConfig(*this, gm);
}

int
FlowCtrlConfig::serialize(char *buf, unsigned int size) const
{
    gpb::dtcpFlowControlConfig_t gm;

    FlowCtrlConfig2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2RtxCtrlConfig(RtxCtrlConfig& cfg,
                  const gpb::dtcpRtxControlConfig_t &gm)
{
    cfg.max_time_to_retry = gm.maxtimetoretry();
    cfg.data_rxmsn_max = gm.datarxmsnmax();
    cfg.initial_tr = gm.initialrtxtime();
    gpb2PolicyDescr(cfg.rtx_timer_expiry, gm.rtxtimerexpirypolicy());
    gpb2PolicyDescr(cfg.sender_ack, gm.senderackpolicy());
    gpb2PolicyDescr(cfg.receiving_ack_list, gm.recvingacklistpolicy());
    gpb2PolicyDescr(cfg.rcvr_ack, gm.rcvrackpolicy());
    gpb2PolicyDescr(cfg.sending_ack, gm.sendingackpolicy());
    gpb2PolicyDescr(cfg.rcvr_ctrl_ack, gm.rcvrcontrolackpolicy());
}

static int
RtxCtrlConfig2gpb(const RtxCtrlConfig& cfg,
                  gpb::dtcpRtxControlConfig_t &gm)
{
    gpb::policyDescriptor_t *p;

    gm.set_maxtimetoretry(cfg.max_time_to_retry);
    gm.set_datarxmsnmax(cfg.data_rxmsn_max);
    gm.set_initialrtxtime(cfg.initial_tr);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.rtx_timer_expiry, *p);
    gm.set_allocated_rtxtimerexpirypolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.sender_ack, *p);
    gm.set_allocated_senderackpolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.receiving_ack_list, *p);
    gm.set_allocated_recvingacklistpolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.rcvr_ack, *p);
    gm.set_allocated_rcvrackpolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.sending_ack, *p);
    gm.set_allocated_sendingackpolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.rcvr_ctrl_ack, *p);
    gm.set_allocated_rcvrcontrolackpolicy(p);

    return 0;
}

RtxCtrlConfig::RtxCtrlConfig(const char *buf, unsigned int size)
{
    gpb::dtcpRtxControlConfig_t gm;

    gm.ParseFromArray(buf, size);

    gpb2RtxCtrlConfig(*this, gm);
}

int
RtxCtrlConfig::serialize(char *buf, unsigned int size) const
{
    gpb::dtcpRtxControlConfig_t gm;

    RtxCtrlConfig2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2DtcpConfig(DtcpConfig& cfg,
               const gpb::dtcpConfig_t &gm)
{
    cfg.flow_ctrl = gm.flowcontrol();
    cfg.rtx_ctrl = gm.rtxcontrol();
    gpb2FlowCtrlConfig(cfg.flow_ctrl_cfg, gm.flowcontrolconfig());
    gpb2RtxCtrlConfig(cfg.rtx_ctrl_cfg, gm.rtxcontrolconfig());
    gpb2PolicyDescr(cfg.lost_ctrl_pdu, gm.lostcontrolpdupolicy());
    gpb2PolicyDescr(cfg.rtt_estimator, gm.rttestimatorpolicy());
}

static int
DtcpConfig2gpb(const DtcpConfig& cfg,
               gpb::dtcpConfig_t &gm)
{
    gpb::policyDescriptor_t *p;
    gpb::dtcpFlowControlConfig_t *f;
    gpb::dtcpRtxControlConfig_t *r;

    gm.set_flowcontrol(cfg.flow_ctrl);
    gm.set_rtxcontrol(cfg.rtx_ctrl);

    f = new gpb::dtcpFlowControlConfig_t;
    FlowCtrlConfig2gpb(cfg.flow_ctrl_cfg, *f);
    gm.set_allocated_flowcontrolconfig(f);

    r = new gpb::dtcpRtxControlConfig_t;
    RtxCtrlConfig2gpb(cfg.rtx_ctrl_cfg, *r);
    gm.set_allocated_rtxcontrolconfig(r);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.lost_ctrl_pdu, *p);
    gm.set_allocated_lostcontrolpdupolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.rtt_estimator, *p);
    gm.set_allocated_rttestimatorpolicy(p);

    return 0;
}

DtcpConfig::DtcpConfig(const char *buf, unsigned int size)
{
    gpb::dtcpConfig_t gm;

    gm.ParseFromArray(buf, size);

    gpb2DtcpConfig(*this, gm);
}

int
DtcpConfig::serialize(char *buf, unsigned int size) const
{
    gpb::dtcpConfig_t gm;

    DtcpConfig2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2ConnPolicies(ConnPolicies& cfg,
                 const gpb::connectionPolicies_t &gm)
{
    cfg.dtcp_present = gm.dtcppresent();
    cfg.seq_num_rollover_th = gm.seqnumrolloverthreshold();
    cfg.initial_a_timer = gm.initialatimer();
    gpb2DtcpConfig(cfg.dtcp_cfg, gm.dtcpconfiguration());
    gpb2PolicyDescr(cfg.rcvr_timer_inact, gm.rcvrtimerinactivitypolicy());
    gpb2PolicyDescr(cfg.sender_timer_inact, gm.sendertimerinactiviypolicy());
    gpb2PolicyDescr(cfg.init_seq_num, gm.initialseqnumpolicy());
}

static int
ConnPolicies2gpb(const ConnPolicies& cfg,
                 gpb::connectionPolicies_t &gm)
{
    gpb::policyDescriptor_t *p;
    gpb::dtcpConfig_t *d;

    gm.set_dtcppresent(cfg.dtcp_present);
    gm.set_seqnumrolloverthreshold(cfg.seq_num_rollover_th);
    gm.set_initialatimer(cfg.initial_a_timer);

    d = new gpb::dtcpConfig_t;
    DtcpConfig2gpb(cfg.dtcp_cfg, *d);
    gm.set_allocated_dtcpconfiguration(d);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.rcvr_timer_inact, *p);
    gm.set_allocated_rcvrtimerinactivitypolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.sender_timer_inact, *p);
    gm.set_allocated_sendertimerinactiviypolicy(p);

    p = new gpb::policyDescriptor_t;
    PolicyDescr2gpb(cfg.init_seq_num, *p);
    gm.set_allocated_initialseqnumpolicy(p);

    return 0;
}

ConnPolicies::ConnPolicies(const char *buf, unsigned int size)
{
    gpb::connectionPolicies_t gm;

    gm.ParseFromArray(buf, size);

    gpb2ConnPolicies(*this, gm);
}

int
ConnPolicies::serialize(char *buf, unsigned int size) const
{
    gpb::connectionPolicies_t gm;

    ConnPolicies2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2ConnId(ConnId& id,
           const gpb::connectionId_t &gm)
{
    id.qos_id = gm.qosid();
    id.src_cep = gm.sourcecepid();
    id.dst_cep = gm.destinationcepid();
}

static int
ConnId2gpb(const ConnId& id,
           gpb::connectionId_t &gm)
{
    gm.set_qosid(id.qos_id);
    gm.set_sourcecepid(id.src_cep);
    gm.set_destinationcepid(id.dst_cep);

    return 0;
}

ConnId::ConnId(const char *buf, unsigned int size)
{
    gpb::connectionId_t gm;

    gm.ParseFromArray(buf, size);

    gpb2ConnId(*this, gm);
}

int
ConnId::serialize(char *buf, unsigned int size) const
{
    gpb::connectionId_t gm;

    ConnId2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2FlowRequest(FlowRequest& fr,
                const gpb::Flow &gm)
{
    gpb2RinaName(fr.src_app, gm.sourcenaminginfo());
    gpb2RinaName(fr.dst_app, gm.destinationnaminginfo());
    fr.src_port = gm.sourceportid();
    fr.dst_port = gm.destinationportid();
    fr.src_addr = gm.sourceaddress();
    fr.dst_addr = gm.destinationaddress();
    for (int i = 0; i < gm.connectionids_size(); i++) {
        fr.connections.push_back(ConnId());
        gpb2ConnId(fr.connections.back(), gm.connectionids(i));
    }
    fr.cur_conn_idx = gm.currentconnectionidindex();
    fr.state = gm.state();
    gpb2QosSpec(fr.qos, gm.qosparameters());
    gpb2ConnPolicies(fr.policies, gm.connectionpolicies());
    fr.access_ctrl = NULL;
    fr.max_create_flow_retries = gm.maxcreateflowretries();
    fr.create_flow_retries = gm.createflowretries();
    fr.hop_cnt = gm.hopcount();
}

static int
FlowRequest2gpb(const FlowRequest& fr,
                gpb::Flow &gm)
{
    gpb::applicationProcessNamingInfo_t *name;
    gpb::qosSpecification_t *q;
    gpb::connectionPolicies_t *p;

    name = RinaName2gpb(fr.src_app);
    gm.set_allocated_sourcenaminginfo(name);

    name = RinaName2gpb(fr.dst_app);
    gm.set_allocated_destinationnaminginfo(name);

    gm.set_sourceportid(fr.src_port);
    gm.set_destinationportid(fr.dst_port);
    gm.set_sourceaddress(fr.src_addr);
    gm.set_destinationaddress(fr.dst_addr);
    for (list<ConnId>::const_iterator lit = fr.connections.begin();
                        lit != fr.connections.end(); lit++) {
        gpb::connectionId_t *c = gm.add_connectionids();

        ConnId2gpb(*lit, *c);
    }
    gm.set_currentconnectionidindex(fr.cur_conn_idx);
    gm.set_state(fr.state);

    q = new gpb::qosSpecification_t;
    QosSpec2gpb(fr.qos, *q);
    gm.set_allocated_qosparameters(q);

    p = new gpb::connectionPolicies_t;
    ConnPolicies2gpb(fr.policies, *p);
    gm.set_allocated_connectionpolicies(p);

    /* access_ctrl not considered --> it will be empty */

    gm.set_maxcreateflowretries(fr.max_create_flow_retries);
    gm.set_createflowretries(fr.create_flow_retries);
    gm.set_hopcount(fr.hop_cnt);

    return 0;
}

FlowRequest::FlowRequest(const char *buf, unsigned int size)
{
    gpb::Flow gm;

    gm.ParseFromArray(buf, size);

    gpb2FlowRequest(*this, gm);
}

int
FlowRequest::serialize(char *buf, unsigned int size) const
{
    gpb::Flow gm;

    FlowRequest2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

AData::AData(const char *buf, unsigned int size)
{
    gpb::a_data_t gm;

    gm.ParseFromArray(buf, size);

    src_addr = gm.sourceaddress();
    dst_addr = gm.destaddress();
    cdap = msg_deser_stateless(gm.cdapmessage().data(),
                               gm.cdapmessage().size());
}

int
AData::serialize(char *buf, unsigned int size) const
{
    gpb::a_data_t gm;
    char *serbuf = NULL;
    size_t serlen;
    int ret;

    gm.set_sourceaddress(src_addr);
    gm.set_destaddress(dst_addr);
    if (cdap) {
        msg_ser_stateless(cdap, &serbuf, &serlen);
        gm.set_cdapmessage(serbuf, serlen);
    }

    ret = ser_common(gm, buf, size);

    if (serbuf) {
        delete [] serbuf;
    }

    return ret;
}
