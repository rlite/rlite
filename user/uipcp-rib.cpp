#include <vector>
#include <map>
#include <iostream>
#include <cstring>

#include "rinalite/rinalite-common.h"

#include "uipcp-rib.h"

using namespace std;


struct uipcp_rib {
};

extern "C" struct uipcp_rib *
rib_create(void)
{
    struct uipcp_rib *rib = new uipcp_rib();

    if (!rib) {
        return NULL;
    }

    PD("RIB created\n");

    memset(rib, 0, sizeof(*rib));

    return rib;
}

extern "C" void
rib_destroy(struct uipcp_rib *rib)
{
    PD("RIB destroyed\n");

    delete rib;
}
