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

#ifndef __UIPCP_CODECS_H__
#define __UIPCP_CODECS_H__

#include <stdint.h>
#include <list>
#include <string>
#include <memory>

#include "rlite/common.h"
#include "rina/cdap.hpp"

#ifdef RL_MEMTRACK
#define rl_new(_exp, _ty)                                                      \
    ({                                                                         \
        rl_mt_adjust(1, _ty);                                                  \
        new _exp;                                                              \
    })
#define rl_delete(_exp, _ty)                                                   \
    do {                                                                       \
        rl_mt_adjust(-1, _ty);                                                 \
        delete _exp;                                                           \
    } while (0)
#else /* RL_MEMTRACK */
#define rl_new(_exp, _ty) new _exp
#define rl_delete(_exp, _ty) delete _exp
#endif /* RL_MEMTRACK */

struct RinaName {
    std::string apn;
    std::string api;
    std::string aen;
    std::string aei;

    RinaName() = default;
    RinaName(const std::string &apn_, const std::string &api_,
             const std::string &aen_, const std::string &aei_);
    RinaName(const struct rina_name *name);
    RinaName(const char *name);
    RinaName(const std::string &name);
    operator std::string() const;
    bool operator==(const RinaName &other) const;
    bool operator!=(const RinaName &other) const;
    int rina_name_fill(struct rina_name *name);
};

#include "BaseRIB.pb.h"
gpb::APName *apname2gpb(const std::string &name);
std::string apname2string(const gpb::APName &gname);

#endif /* __UIPCP_CODECS_H__ */
