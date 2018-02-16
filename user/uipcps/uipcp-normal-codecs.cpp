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

gpb::APName *
RinaName2gpb(const RinaName &name)
{
    gpb::APName *gan = new gpb::APName();

    gan->set_ap_name(name.apn);
    gan->set_ap_instance(name.api);
    gan->set_ae_name(name.aen);
    gan->set_ae_instance(name.aei);

    return gan;
}

std::string
gpb2string(const gpb::APName &gname)
{
    return rina_string_from_components(gname.ap_name(), gname.ap_instance(),
                                       gname.ae_name(), gname.ae_instance());
}
