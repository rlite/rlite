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

gpb::APName *
apname2gpb(const std::string &str)
{
    gpb::APName *gan = new gpb::APName();

    rina_components_from_string(
        str, *gan->mutable_ap_name(), *gan->mutable_ap_instance(),
        *gan->mutable_ae_name(), *gan->mutable_ae_instance());

    return gan;
}

std::string
apname2string(const gpb::APName &gname)
{
    return rina_string_from_components(gname.ap_name(), gname.ap_instance(),
                                       gname.ae_name(), gname.ae_instance());
}
