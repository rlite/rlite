#include <iostream>
#include <list>
#include <string>
#include <sstream>

#include "rinalite/rinalite-common.h"

#include "uipcp-codecs.hpp"

#include "EnrollmentInformationMessage.pb.h"
#include "ApplicationProcessNamingInfoMessage.pb.h"
#include "DirectoryForwardingTableEntryArrayMessage.pb.h"
#include "DirectoryForwardingTableEntryMessage.pb.h"
#include "NeighborMessage.pb.h"
#include "NeighborArrayMessage.pb.h"
#include "FlowStateMessage.pb.h"
#include "FlowStateGroupMessage.pb.h"
#include "CommonMessages.pb.h"

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

bool RinaName::operator==(const RinaName& other)
{
    return api == other.api && apn == other.apn &&
            aen == other.aen && aei == other.aei;
}

bool RinaName::operator!=(const RinaName& other)
{
    return !(*this == other);
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

DFTEntry::DFTEntry(const char *buf, unsigned int size)
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

Property::Property(const char *buf, unsigned int size)
{
    gpb::property_t gm;

    gm.ParseFromArray(buf, size);

    name = gm.name();
    value = gm.value();
}

int
Property::serialize(char *buf, unsigned int size) const
{
    gpb::property_t gm;

    gm.set_name(name);
    gm.set_value(value);

    return ser_common(gm, buf, size);
}

