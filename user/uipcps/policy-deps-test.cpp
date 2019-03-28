/*
 * Tests for policy dependency resolution.
 *
 * Copyright (C) 2019 Michal Koutenský
 * Author: Michal Koutenský <koutak.m@gmail.com>
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
#include <sstream>
#include <list>
#include <vector>
#include <cassert>
#include <chrono>
#include <unistd.h>
#include <cmath>

#include "uipcp-container.h"
#include "uipcp-normal.hpp"

struct TestPolicyDeps : public rlite::UipcpRib {
    struct uipcp uipcp;
    std::function<std::unique_ptr<rlite::Component>(UipcpRib *)> builder =
        [](UipcpRib *) { return nullptr; };
    TestPolicyDeps(struct uipcp *_u) : rlite::UipcpRib(_u, nullptr) {}

    int init();
};

int
TestPolicyDeps::init()
{
    std::string test_policy;
    std::vector<std::pair<std::string, std::string>> dependencies;
    int ret;

    /* Single policy without dependencies */
    test_policy = "test-no-depends";
    ret = policy_register(rlite::UipcpRib::EnrollmentPrefix, test_policy);
    if (ret) {
        std::cout << "Failed to register component "
                  << rlite::UipcpRib::EnrollmentPrefix << " policy "
                  << test_policy << std::endl;
        return -1;
    }

    /* Nonexisting dependency */
    test_policy = "test-false-depends";
    dependencies.emplace_back(rlite::UipcpRib::ResourceAllocPrefix,
                              test_policy);
    ret = policy_register(rlite::UipcpRib::EnrollmentPrefix, test_policy,
                          builder, {}, {}, dependencies);
    if (ret) {
        std::cout << "Failed to register component "
                  << rlite::UipcpRib::EnrollmentPrefix << " policy "
                  << test_policy << std::endl;
        return -1;
    }
    dependencies.clear();

    /* A chain of policies with linear dependencies */
    test_policy = "test-linear-depends";
    ret         = policy_register(rlite::AddrAllocator::Prefix, test_policy);
    if (ret) {
        std::cout << "Failed to register component "
                  << rlite::AddrAllocator::Prefix << " policy " << test_policy
                  << std::endl;
        return -1;
    }
    dependencies.emplace_back(rlite::AddrAllocator::Prefix, test_policy);
    ret = policy_register(rlite::UipcpRib::ResourceAllocPrefix, test_policy,
                          builder, {}, {}, dependencies);
    if (ret) {
        std::cout << "Failed to register component "
                  << rlite::UipcpRib::ResourceAllocPrefix << " policy "
                  << test_policy << std::endl;
        return -1;
    }
    dependencies.clear();
    dependencies.emplace_back(rlite::UipcpRib::ResourceAllocPrefix,
                              test_policy);
    ret = policy_register(rlite::UipcpRib::EnrollmentPrefix, test_policy,
                          builder, {}, {}, dependencies);
    if (ret) {
        std::cout << "Failed to register component "
                  << rlite::UipcpRib::EnrollmentPrefix << " policy "
                  << test_policy << std::endl;
        return -1;
    }
    dependencies.clear();

    /* A chain of policies with duplicate indirect dependencies */
    test_policy = "test-duplicate-indirect-depends";
    dependencies.emplace_back(rlite::AddrAllocator::Prefix,
                              test_policy + "-second");
    ret = policy_register(rlite::AddrAllocator::Prefix, test_policy + "-first",
                          builder, {}, {}, dependencies);
    if (ret) {
        std::cout << "Failed to register component "
                  << rlite::AddrAllocator::Prefix << " policy " << test_policy
                  << "-first" << std::endl;
        return -1;
    }
    dependencies.clear();
    ret =
        policy_register(rlite::AddrAllocator::Prefix, test_policy + "-second");
    if (ret) {
        std::cout << "Failed to register component "
                  << rlite::AddrAllocator::Prefix << " policy " << test_policy
                  << "-second" << std::endl;
        return -1;
    }
    dependencies.emplace_back(rlite::AddrAllocator::Prefix,
                              test_policy + "-first");
    ret = policy_register(rlite::UipcpRib::ResourceAllocPrefix, test_policy,
                          builder, {}, {}, dependencies);
    if (ret) {
        std::cout << "Failed to register component "
                  << rlite::UipcpRib::EnrollmentPrefix << " policy "
                  << test_policy << std::endl;
        return -1;
    }
    dependencies.clear();

    /* Cyclical dependencies */
    test_policy = "test-cyclic-depends";
    std::vector<
        std::tuple<const std::string &, const std::string &,
                   std::function<std::unique_ptr<rlite::Component>(UipcpRib *)>,
                   std::vector<std::string>,
                   std::vector<std::pair<std::string, rlite::PolicyParam>>,
                   std::vector<std::pair<std::string, std::string>>>>
        policies;

    using PolicyTuple =
        std::tuple<const std::string &, const std::string &,
                   std::function<std::unique_ptr<rlite::Component>(UipcpRib *)>,
                   std::vector<std::string>,
                   std::vector<std::pair<std::string, rlite::PolicyParam>>,
                   std::vector<std::pair<std::string, std::string>>>;

    policies.push_back(PolicyTuple(rlite::UipcpRib::EnrollmentPrefix,
                                   test_policy, builder, {}, {}, {}));
    policies.push_back(PolicyTuple(rlite::UipcpRib::ResourceAllocPrefix,
                                   test_policy, builder, {}, {}, {}));
    policies.push_back(PolicyTuple(rlite::AddrAllocator::Prefix, test_policy,
                                   builder, {}, {}, {}));
    ret = policy_register_group(policies);
    if (ret) {
        std::cout << "Failed to register policy group " << test_policy
                  << std::endl;
        return -1;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    auto usage = []() {
        std::cout << "policy-deps-test -v be verbose\n"
                     "          -h show this help and exit\n";
    };
    int verbosity = 0;
    int opt;

    while ((opt = getopt(argc, argv, "hvn:")) != -1) {
        switch (opt) {
        case 'h':
            usage();
            return 0;

        case 'v':
            verbosity++;
            break;

        default:
            std::cout << "    Unrecognized option " << static_cast<char>(opt)
                      << std::endl;
            usage();
            return -1;
        }
    }

    struct uipcp uipcp;
    std::string name = "policy-deps-test";
    uipcp.name       = new char[name.length() + 1];
    name.copy(uipcp.name, name.length());
    uipcp.name[name.length()] = '\0';
    TestPolicyDeps test(&uipcp);
    if (test.init()) {
        std::cout << "Initialization of RIB for testing failed" << std::endl;
        return -1;
    }

    int ret = 0;
    std::string test_policy;

    /* Single policy without dependencies */
    test_policy = "test-no-depends";
    ret = test.policy_mod(rlite::UipcpRib::EnrollmentPrefix, test_policy);
    if (!(ret == 0 &&
          test.policies[rlite::UipcpRib::EnrollmentPrefix] == test_policy)) {
        std::cout << "Test " << test_policy << " failed" << std::endl;
        return -1;
    }

    /* Nonexisting dependency */
    test_policy = "test-false-depends";
    ret = test.policy_mod(rlite::UipcpRib::EnrollmentPrefix, test_policy);
    if (ret == 0) {
        std::cout << "Test " << test_policy << " failed" << std::endl;
        return -1;
    }

    /* A chain of policies with linear dependencies */
    test_policy = "test-linear-depends";
    ret = test.policy_mod(rlite::UipcpRib::EnrollmentPrefix, test_policy);
    if (!(ret == 0 &&
          test.policies[rlite::UipcpRib::EnrollmentPrefix] == test_policy &&
          test.policies[rlite::UipcpRib::ResourceAllocPrefix] == test_policy &&
          test.policies[rlite::AddrAllocator::Prefix] == test_policy)) {
        std::cout << "Test " << test_policy << " failed" << std::endl;
        return -1;
    }

    /* A chain of policies with duplicate direct dependencies */
    test_policy = "test-duplicate-direct-depends";
    std::vector<std::pair<std::string, std::string>> dependencies;
    test.policy_register(rlite::AddrAllocator::Prefix, test_policy + "-first");
    if (ret) {
        std::cout << "Failed to register component "
                  << rlite::AddrAllocator::Prefix << " policy " << test_policy
                  << "-first" << std::endl;
        return -1;
    }
    test.policy_register(rlite::AddrAllocator::Prefix, test_policy + "-second");
    if (ret) {
        std::cout << "Failed to register component "
                  << rlite::AddrAllocator::Prefix << " policy " << test_policy
                  << "-second" << std::endl;
        return -1;
    }
    dependencies.emplace_back(rlite::AddrAllocator::Prefix,
                              test_policy + "-first");
    dependencies.emplace_back(rlite::AddrAllocator::Prefix,
                              test_policy + "-second");
    ret = test.policy_register(rlite::UipcpRib::ResourceAllocPrefix,
                               test_policy, test.builder, {}, {}, dependencies);
    if (ret == 0) {
        std::cout << "Test " << test_policy << " failed" << std::endl;
        return -1;
    }
    dependencies.clear();

    /* A chain of policies with duplicate indirect dependencies */
    test_policy = "test-duplicate-indirect-depends";
    ret = test.policy_mod(rlite::UipcpRib::ResourceAllocPrefix, test_policy);
    if (ret == 0) {
        std::cout << "Test " << test_policy << " failed" << std::endl;
        return -1;
    }

    /* Cyclical dependencies */
    test_policy = "test-cyclic-depends";
    ret = test.policy_mod(rlite::UipcpRib::EnrollmentPrefix, test_policy);
    if (!(ret == 0 &&
          test.policies[rlite::UipcpRib::EnrollmentPrefix] == test_policy &&
          test.policies[rlite::UipcpRib::ResourceAllocPrefix] == test_policy &&
          test.policies[rlite::AddrAllocator::Prefix] == test_policy)) {
        std::cout << "Test " << test_policy << " failed" << std::endl;
        return -1;
    }

    return 0;
}
