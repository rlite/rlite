#!/usr/bin/env python
import re
import os
import sys
import argparse
from libdemo import Demo, prefix_is_valid


class Configen(Demo):
    def __init__(self, flavour_suffix, addr_alloc_policy, reliable_flows,
                 reliable_n_flows, keepalive, broadcast_enrollment,
                 enrollment_strategy):
        self.vms = dict()
        self.shims = dict()
        self.links = []
        self.difs = dict()
        self.enrollments = dict()
        self.lowerflowallocs = dict()
        self.dif_graphs = dict()
        self.dif_policies = dict()
        self.dns_mappings = dict()
        self.netems = dict()
        self.hostfwds = dict()
        self.fwd_hports = set()
        self.dif_ordering = []
        self.flavour_suffix = flavour_suffix
        self.addr_alloc_policy = addr_alloc_policy
        self.reliable_flows = reliable_flows
        self.reliable_n_flows = reliable_n_flows
        self.keepalive = keepalive
        self.broadcast_enrollment = broadcast_enrollment
        self.enrollment_strategy = enrollment_strategy
        self.enrollment_order = 'parallel'
        self.register = False
        self.simulate = False

    def parse_config(self, conf):
        fin = open(conf, 'r')

        linecnt = 0

        while 1:
            line = fin.readline()
            if line == '':
                break
            linecnt += 1

            line = line.replace('\n', '').strip()

            if line.startswith('#') or line == "":
                continue

            m = re.match(r'\s*eth\s+([\w-]+)\s+([\w-]+)\s+([\w-]+)\s+(\w+)$',
                         line)
            if m:
                vm = m.group(1)
                ipcp = m.group(2)
                dif = m.group(3)
                netdev = m.group(4)

                if vm in self.vms and ipcp in self.vms[vm]['eths']:
                    print('Error: Line %d: IPCP %s already defined' % (linecnt,
                                                                       ipcp))
                    continue

                if dif not in self.shims:
                    self.shims[dif] = {
                        'name': dif,
                        'vms': [vm],
                        'type': 'eth'
                    }
                else:
                    self.shims[dif]['vms'].append(vm)

                if vm not in self.vms:
                    self.vms[vm] = {
                        'name': vm,
                        'ports': [],
                        'enrolling': [],
                        'eths': {}
                    }
                self.vms[vm]['eths'][ipcp] = {
                    'ipcp': ipcp,
                    'dif': dif,
                    'netdev': netdev
                }
                self.links.append((dif, vm))

                continue

            m = re.match(r'\s*udp4\s+([\w-]+)\s+(\w.*)$', line)
            if m:
                shim = m.group(1)
                members = m.group(2).split()

                if shim in self.shims:
                    print('Error: Line %d: udp4 %s already defined' % (linecnt,
                                                                       shim))
                    continue

                self.shims[shim] = {'name': shim, 'type': 'udp4', 'vms': []}

                self.dns_mappings[shim] = dict()

                for member in members:
                    vm, ip = member.split(':')

                    if not prefix_is_valid(ip):
                        print('Error: Line %d: ip %s is not valid' % (linecnt,
                                                                      ip))
                        continue

                    self.shims[shim]['vms'].append(vm)
                    if vm not in self.vms:
                        self.vms[vm] = {
                            'name': vm,
                            'ports': [],
                            'enrolling': [],
                            'netdevs': []
                        }
                    self.links.append((shim, vm))
                    self.dns_mappings[shim][vm] = {'ip': ip}
                continue

            m = re.match(r'\s*dif\s+([\w-]+)\s+([\w-]+)\s+(\w.*)$', line)
            if m:
                dif = m.group(1)
                vm = m.group(2)
                dif_list = m.group(3).split()

                if vm not in self.vms:
                    self.vms[vm] = {
                        'name': vm,
                        'ports': [],
                        'enrolling': [],
                        'netdevs': []
                    }

                if dif not in self.difs:
                    self.difs[dif] = dict()

                if vm in sorted(self.difs[dif]):
                    print('Error: Line %d: vm %s in dif %s already specified' %
                          (linecnt, vm, dif))
                    continue

                self.difs[dif][vm] = dif_list

                continue

            m = re.match(r'\s*netem\s+([\w-]+)\s+([\w-]+)\s+(\w.*)$', line)
            if m:
                dif = m.group(1)
                vmname = m.group(2)
                netem_args = m.group(3)

                if dif not in self.netems:
                    self.netems[dif] = dict()
                self.netems[dif][vmname] = {
                    'args': netem_args,
                    'linecnt': linecnt
                }

                continue

            m = re.match(r'\s*hostfwd\s+([\w-]+)\s+((:?\d+:\d+\s*)+)$', line)
            if m:
                vmname = m.group(1)
                fwdlist = m.group(2).split()

                if vmname in self.hostfwds:
                    print('Error: Line %d: hostfwd for %s already defined' %
                          (linecnt, vmname))
                    continue

                # check for uniqueness of guest ports
                sg = set([int(x.split(':')[1]) for x in fwdlist])
                if 22 in sg or len(sg) != len(fwdlist):
                    print(
                        'Error: Line %d: hostfwd for %s has conflicting mappings'
                        % (linecnt, vmname))
                    continue

                self.hostfwds[vmname] = fwdlist

                continue

            m = re.match(
                r'\s*policy\s+(\w+)\s+(\*|(?:(?:\w+,)*\w+))\s+([*\w.-]+)\s+([\w-]+)((?:\s+[\w.-]+\s*=\s*[/\w.,\$-]+)*)\s*$',
                line)
            if m:
                dif = m.group(1)
                nodes = m.group(2)
                path = m.group(3)
                ps = m.group(4)
                parms = list()
                if m.group(5) is not None:
                    parms_str = m.group(5).strip()
                    if parms_str != '':
                        parms = parms_str.split(' ')

                if dif not in self.dif_policies:
                    self.dif_policies[dif] = []

                if nodes == '*':
                    nodes = []
                else:
                    nodes = nodes.split(',')

                self.dif_policies[dif].append({
                    'path': path,
                    'nodes': nodes,
                    'ps': ps,
                    'parms': parms
                })
                continue

            # No match, spit a warning
            print('Warning: Line %d unrecognized and ignored' % linecnt)

        fin.close()

    def compute_shim_ipcps(self, vm):
        ctrl_cmds = []

        # create and configure shim ipcps
        for port in vm['ports']:
            shim = self.shims[port['shim']]
            vars_dict = {
                'mac': port['mac'],
                'idx': port['idx'],
                'shim': port['shim'],
                'id': vm['id'],
                'shimtype': shim['type']
            }
            if vars_dict['shimtype'] == 'udp':
                ctrl_cmds.append(
                    'ipcp-create %(shim)s.%(id)s.IPCP shim-%(shimtype)s %(shim)s.DIF\n'
                    % vars_dict)
            del vars_dict

        for ipcp in vm['eths']:
            eth = vm['eths'][ipcp]
            vars_dict = {
                'ipcp': eth['ipcp'],
                'dif': eth['dif'],
                'netdev': eth['netdev']
            }
            ctrl_cmds.append(
                'ipcp-create %(ipcp)s.IPCP shim-eth %(dif)s.DIF\n'
                'ipcp-config %(ipcp)s.IPCP netdev %(netdev)s\n' % vars_dict)
            del vars_dict
        return ctrl_cmds


description = "Python script to generate rlite initscripts"
epilog = "2015-2016 Vincenzo Maffione <v.maffione@gmail.com>"

argparser = argparse.ArgumentParser(description=description, epilog=epilog)
argparser.add_argument(
    '-c',
    '--conf',
    help="demo.conf configuration file",
    type=str,
    default='demo.conf')
argparser.add_argument(
    '-e',
    '--enrollment-strategy',
    help="Minimal uses a spanning tree of each DIF",
    type=str,
    choices=['minimal', 'full-mesh'],
    default='minimal')
argparser.add_argument(
    '-k',
    '--keepalive',
    default=10,
    help="Neighbor keepalive timeout in seconds (0 to disable)",
    type=int)
argparser.add_argument(
    '-N',
    '--reliable-n-flows',
    action='store_true',
    help="Use reliable N-flows if reliable N-1-flows are not available")
argparser.add_argument(
    '-R',
    '--reliable-flows',
    action='store_true',
    help="If possible, use dedicated reliable N-1-flows "
    "for management traffic rather than reusing "
    "kernel-bound unreliable N-1 flows")
argparser.add_argument(
    '-A',
    '--addr-alloc-policy',
    type=str,
    choices=["distributed", "manual"],
    default="distributed",
    help="Address allocation policy to be used for all DIFs")
argparser.add_argument(
    '--flavour', help="flavour to use for normal IPCPs", type=str, default='')
argparser.add_argument(
    '--broadcast-enrollment',
    action='store_true',
    help="With broadcast enrollment, no neighbor "
    "is specified for the ipcp-enroll command, so "
    "that N-1 flow allocation is issued using the "
    "N-DIF name as destination application")
argparser.add_argument(
        '-o',
        '--output',
        type=str,
        help="Output directory for generated initscripts",
        default="."
        )
args = argparser.parse_args()

flavour_suffix = ''
if args.flavour != '':
    flavour_suffix = '-' + args.flavour

if not os.access(args.output, os.W_OK):
    try:
        os.makedirs(args.output)
    except os.error:
        sys.stderr.write("Cannot access or create output directory\n")
        sys.exit(1)

demo = Configen(
    flavour_suffix=flavour_suffix,
    addr_alloc_policy=args.addr_alloc_policy,
    reliable_flows=args.reliable_flows,
    reliable_n_flows=args.reliable_n_flows,
    keepalive=args.keepalive,
    broadcast_enrollment=args.broadcast_enrollment,
    enrollment_strategy=args.enrollment_strategy)

demo.parse_config(args.conf)
demo.realize_config()

for vmname in sorted(demo.vms):
    vm = demo.vms[vmname]
    outs = ''
    ctrl_cmds = []

    ctrl_cmds += demo.compute_shim_ipcps(vm)
    ctrl_cmds += demo.compute_normal_ipcps(vmname)
    pctrl_cmds, enroll_cmds, appl_cmds = demo.compute_enrollments(vmname)
    ctrl_cmds += pctrl_cmds

    initscript_name = args.output + '/' + vm['name'] + '.initscript'
    initscript = open(initscript_name, 'w')
    initscript_outs = ''
    for cmd in ctrl_cmds:
        initscript_outs += cmd
    for cmd in enroll_cmds:
        initscript_outs += cmd
    initscript.write(initscript_outs)
    initscript.close()
