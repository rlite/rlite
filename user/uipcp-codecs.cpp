#include <iostream>
#include <list>
#include <string>

#include "rinalite/rinalite-common.h"

#include "uipcp-codecs.hpp"

#include "EnrollmentInformationMessage.pb.h"
#include "ApplicationProcessNamingInfoMessage.pb.h"
#include "DirectoryForwardingTableEntryArrayMessage.pb.h"
#include "DirectoryForwardingTableEntryMessage.pb.h"

using namespace std;


static int
ser_common(::google::protobuf::MessageLite &gm, char *buf,
           unsigned int size)
{
    if (gm.ByteSize() > size) {
        PE("User buffer too small [%u/%u]\n",
                gm.ByteSize(), size);
        return -1;
    }

    gm.SerializeToArray(buf, size);

    return gm.ByteSize();
}

RinaName::RinaName(const struct rina_name *name)
{
    apn = name->apn ? string(name->apn) : string();
    api = name->api ? string(name->api) : string();
    aen = name->aen ? string(name->aen) : string();
    aei = name->aei ? string(name->aei) : string();
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
    gan->set_applicationprocessinstance(name.aei);
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

DFTEntry::DFTEntry(const char *buf, unsigned int size)
{
    gpb::directoryForwardingTableEntry_t gm;

    gm.ParseFromArray(buf, size);

    gpb2DFTEntry(*this, gm);
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

