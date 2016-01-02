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

DFTEntry::DFTEntry(const char *buf, unsigned int size)
{
    gpb::directoryForwardingTableEntry_t gm;

    gm.ParseFromArray(buf, size);

    gpb2RinaName(appl_name, gm.applicationname());
    address = gm.ipcprocesssynonym();
    timestamp = gm.timestamp();
}

int
DFTEntry::serialize(char *buf, unsigned int size) const
{
    gpb::directoryForwardingTableEntry_t gm;
    gpb::applicationProcessNamingInfo_t *gan =
        RinaName2gpb(appl_name);

    if (!gan) {
        PE("Out of memory\n");
        return -1;
    }

    gm.set_allocated_applicationname(gan);
    gm.set_ipcprocesssynonym(address);
    gm.set_timestamp(timestamp);

    return ser_common(gm, buf, size);
}

