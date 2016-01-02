#include <iostream>
#include <list>
#include <string>

#include "rinalite/rinalite-common.h"

#include "uipcp-codecs.hpp"

#include "EnrollmentInformationMessage.pb.h"

using namespace std;


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

    if (gm.ByteSize() > size) {
        PE("User buffer too small [%u/%u]\n",
                gm.ByteSize(), size);
        return -1;
    }

    gm.SerializeToArray(buf, size);

    return gm.ByteSize();
}
