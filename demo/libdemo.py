#!/usr/bin/env python

#
# Author: Vincenzo Maffione <v.maffione@gmail.com>
#

import re


# @prefix is a string
def prefix_parse(prefix):
    m = re.match('^(\d+)\.(\d+)\.(\d+)\.(\d+)/(\d+)$', prefix)
    if not m:
        return None, None, None

    a = int(m.group(1))
    b = int(m.group(2))
    c = int(m.group(3))
    d = int(m.group(4))
    m = int(m.group(5))

    v = lambda x: x >= 0 and x <= 255
    if not v(a) or not v(b) or not v(c) or not v(d) or m < 0 or m > 32:
        return None, None, None

    num = (a << 24) + (b << 16) + (c << 8) + d
    mask = ((1 << m) - 1) << (32 - m)

    return (num, mask, m)


# @prefix is a string
def prefix_is_valid(prefix):
    num, mask, size = prefix_parse(prefix)

    if num is None or mask is None:
        return False

    return True


# For the sake of reproducibility we need a set with a deterministic pop()
# method. This one is basically a FIFO queue with logarithmic lookup cost.
class FrontierSet:
    def __init__(self, li=[]):
        self.belong = set()
        self.queue = []

        for x in li:
            self.add(x)

    def empty(self):
        return len(self.belong) == 0

    def add(self, x):
        if x in self.belong:
            return
        self.belong.add(x)
        self.queue.append(x)

    def pop(self):
        if self.empty():
            return None  # We may throw an exception

        x = self.queue.pop(0)
        self.belong.remove(x)

        return x


# BFS on a DIF graph to compute the number of levels we need to complete
# the BFS. We stop early once the level reaches 'ub', as the caller
# knows it's not worth going ahead.
def graph_node_depth(graph, node, ub):
    frontier = FrontierSet()
    marked = set()
    frontier.add(node)
    marked.add(node)
    level = 0
    while not frontier.empty():
        new_frontier = FrontierSet()
        level += 1
        if level == ub:
            return level  # not worth going on

        while not frontier.empty():
            cur = frontier.pop()
            for (neigh, lower_dif) in graph[cur]:
                if neigh not in marked:
                    new_frontier.add(neigh)
                    marked.add(neigh)
        frontier = new_frontier

    return level


class Demo:
    def __init__(self, flavour_suffix, addr_alloc_policy, reliable_flows,
                 reliable_n_flows, keepalive, register, simulate,
                 broadcast_enrollment, enrollment_strategy):
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
        self.register = register
        self.simulate = simulate
        self.broadcast_enrollment = broadcast_enrollment
        self.enrollment_strategy = enrollment_strategy
        self.enrollment_order = ''

    # Parse demo.conf
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

            m = re.match(r'\s*eth\s+([\w-]+)\s+(\d+)([GMK])bps\s+(\w.*)$',
                         line)
            if m:
                shim = m.group(1)
                speed = int(m.group(2))
                speed_unit = m.group(3).lower()
                vm_list = m.group(4).split()

                if shim in self.shims:
                    print('Error: Line %d: shim %s already defined' % (linecnt,
                                                                       shim))
                    continue

                self.shims[shim] = {
                    'name': shim,
                    'speed': speed,
                    'vms': vm_list,
                    'speed_unit': speed_unit,
                    'type': 'eth'
                }

                for vm in vm_list:
                    if vm not in self.vms:
                        self.vms[vm] = {
                            'name': vm,
                            'ports': [],
                            'enrolling': []
                        }
                    self.links.append((shim, vm))

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
                            'enrolling': []
                        }
                    self.links.append((shim, vm))
                    self.dns_mappings[shim][vm] = {'ip': ip}
                continue

            m = re.match(r'\s*dif\s+([\w-]+)\s+([\w.-]+)\s+(\w.*)$', line)
            if m:
                dif = m.group(1)
                vm = m.group(2)
                dif_list = m.group(3).split()

                if vm not in self.vms:
                    self.vms[vm] = {'name': vm, 'ports': [], 'enrolling': []}

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
        self.check_port_unique()

    def check_port_unique(self):
        # check for uniqueness of host ports
        for vmname in self.hostfwds:
            for fwdr in self.hostfwds[vmname]:
                p = int(fwdr.split(':')[0])
                if p in self.fwd_hports:
                    print('Error: hostfwds have mapping conflicts for port %d'
                          % p)
                    quit()
                self.fwd_hports.add(p)

    # Compute registration/enrollment order for DIFs
    def compute_order(self):

        # Compute DIFs dependency graph, as both adjacency and incidence list.
        difsdeps_adj = dict()
        difsdeps_inc = dict()
        for dif in sorted(self.difs):
            difsdeps_inc[dif] = set()
            difsdeps_adj[dif] = set()
        for shim in self.shims:
            difsdeps_inc[shim] = set()
            difsdeps_adj[shim] = set()

        for dif in sorted(self.difs):
            for vmname in sorted(self.difs[dif]):
                for lower_dif in sorted(self.difs[dif][vmname]):
                    difsdeps_inc[dif].add(lower_dif)
                    difsdeps_adj[lower_dif].add(dif)

        # Kahn's algorithm below only needs per-node count of
        # incident edges, so we compute these counts from the
        # incidence list and drop the latter.
        difsdeps_inc_cnt = dict()
        for dif in difsdeps_inc:
            difsdeps_inc_cnt[dif] = len(difsdeps_inc[dif])
        del difsdeps_inc

        # Run Kahn's algorithm to compute topological ordering on the DIFs graph.
        frontier = FrontierSet()
        for dif in sorted(difsdeps_inc_cnt):
            if difsdeps_inc_cnt[dif] == 0:
                frontier.add(dif)

        while not frontier.empty():
            cur = frontier.pop()
            self.dif_ordering.append(cur)
            for nxt in sorted(difsdeps_adj[cur]):
                difsdeps_inc_cnt[nxt] -= 1
                if difsdeps_inc_cnt[nxt] == 0:
                    frontier.add(nxt)
            difsdeps_adj[cur] = set()

        circular_set = [
            dif for dif in difsdeps_inc_cnt if difsdeps_inc_cnt[dif] != 0
        ]
        if len(circular_set):
            print("Fatal error: The specified DIFs topology has one or more"
                  "circular dependencies, involving the following"
                  " DIFs: %s" % circular_set)
            print("             DIFs dependency graph: %s" % difsdeps_adj)
            quit(1)

        for dif in self.dif_ordering:
            if dif not in self.dif_policies:
                self.dif_policies[dif] = []
                if self.addr_alloc_policy == "manual":
                    self.dif_policies[dif].append({
                        'path': 'addralloc',
                        'nodes': [],
                        'ps': 'manual',
                        'parms': []
                    })

        # Compute DIF graphs
        for dif in sorted(self.difs):
            neighsets = dict()
            self.dif_graphs[dif] = dict()

            # For each N-1-DIF supporting this DIF, compute the set of nodes that
            # share such N-1-DIF. This set will be called the 'neighset' of
            # the N-1-DIF for the current DIF.

            for vmname in sorted(self.difs[dif]):
                self.dif_graphs[dif][vmname] = []  # init for later use
                for lower_dif in sorted(self.difs[dif][vmname]):
                    if lower_dif not in neighsets:
                        neighsets[lower_dif] = []
                    neighsets[lower_dif].append(vmname)

            # Build the graph, represented as adjacency list
            for lower_dif in neighsets:
                # Each neighset corresponds to a complete (sub)graph.
                for vm1 in neighsets[lower_dif]:
                    for vm2 in neighsets[lower_dif]:
                        if vm1 != vm2:
                            self.dif_graphs[dif][vm1].append((vm2, lower_dif))

        # Compute the center of each DIF, to speed up parallel enrollment
        dif_center = dict()
        for dif in sorted(self.difs):
            master = None
            master_level = len(self.vms) + 1
            for vmname in self.dif_graphs[dif]:
                level = graph_node_depth(self.dif_graphs[dif], vmname,
                                         master_level)
                if level < master_level:
                    master = vmname
                    master_level = level
            dif_center[dif] = master

        # Compute enrollments
        for dif in sorted(self.difs):
            self.enrollments[dif] = []
            # To generate the list of enrollments, we simulate one,
            # using breadth-first trasversal.
            enrolled = set([dif_center[dif]])
            frontier = FrontierSet([dif_center[dif]])
            edges_covered = set()
            while not frontier.empty():
                cur = frontier.pop()
                for edge in self.dif_graphs[dif][cur]:
                    if edge[0] not in enrolled:
                        enrolled.add(edge[0])
                        edges_covered.add((edge[0], cur))
                        self.enrollments[dif].append({
                            'enrollee': edge[0],
                            'enroller': cur,
                            'lower_dif': edge[1]
                        })
                        self.vms[edge[0]]['enrolling'].append(dif)
                        frontier.add(edge[0])

            self.lowerflowallocs[dif] = []
            if self.enrollment_strategy == 'full-mesh':
                for cur in self.dif_graphs[dif]:
                    for edge in self.dif_graphs[dif][cur]:
                        if cur < edge[0]:
                            if (cur, edge[0]) not in edges_covered and \
                                    (edge[0], cur) not in edges_covered:
                                self.lowerflowallocs[dif].append({
                                    'enrollee':
                                    cur,
                                    'enroller':
                                    edge[0],
                                    'lower_dif':
                                    edge[1]
                                })
                                edges_covered.add((cur, edge[0]))

    def assign_shim_ids(self):
        shim_id = 1
        for shim in self.shims:
            self.enrollments[shim] = []
            self.lowerflowallocs[shim] = []
            self.shims[shim]['id'] = shim_id
            shim_id += 1

    def assign_vm_ids(self):
        vmid = 1
        for vmname in sorted(self.vms):
            vm = self.vms[vmname]
            vm['id'] = vmid
            vmid += 1

    def compute_shim_ipcps(self, vm):
        outs = ''
        ctrl_cmds = []
        # Create and configure shim IPCPs
        for port in vm['ports']:
            shim = self.shims[port['shim']]
            vars_dict = {
                'mac': port['mac'],
                'idx': port['idx'],
                'shim': port['shim'],
                'id': vm['id'],
                'shimtype': shim['type']
            }
            outs += 'PORT%(idx)s=$(mac2ifname %(mac)s)\n'\
                    '$SUDO ip link set $PORT%(idx)s up\n' % vars_dict
            ctrl_cmds.append(
                'ipcp-create %(shim)s.%(id)s.IPCP shim-%(shimtype)s %(shim)s.DIF\n'
                % vars_dict)
            if shim['type'] == 'eth':
                ctrl_cmds.append(
                    'ipcp-config %(shim)s.%(id)s.IPCP netdev $PORT%(idx)s\n' %
                    vars_dict)
            elif shim['type'] == 'udp4':
                outs += '$SUDO ip addr add %s dev $PORT%s\n' % (port['ip'],
                                                                port['idx'])
            del vars_dict
        return (outs, ctrl_cmds)

    def compute_normal_ipcps(self, vmname):
        # Create normal IPCPs (it's handy to do it in topological DIF order)
        vm = self.vms[vmname]
        ctrl_cmds = []
        for dif in self.dif_ordering:
            if dif not in self.shims and vmname in self.difs[dif]:
                ctrl_cmds.append(
                    'ipcp-create %(dif)s.%(id)s.IPCP normal%(flsuf)s %(dif)s.DIF\n'
                    % {
                        'dif': dif,
                        'id': vm['id'],
                        'flsuf': self.flavour_suffix
                    })
                if self.addr_alloc_policy == "manual":
                    ctrl_cmds.append(
                        'ipcp-config %(dif)s.%(id)s.IPCP address %(id)d\n' % {
                            'dif': dif,
                            'id': vm['id']
                        })
                elif self.addr_alloc_policy == "distributed":
                    nack_wait_secs = 5 if self.enrollment_order == 'parallel' and len(
                        self.vms) > 30 else 1
                    ctrl_cmds.append(
                        'dif-policy-param-mod %(dif)s.DIF addralloc nack-wait-secs %(nws)d\n'
                        % {
                            'dif': dif,
                            'nws': nack_wait_secs
                        })
                if self.reliable_flows:
                    ctrl_cmds.append(
                        'dif-policy-param-mod %(dif)s.DIF resalloc reliable-flows true\n'
                        % {
                            'dif': dif
                        })
                if self.reliable_n_flows:
                    ctrl_cmds.append(
                        'dif-policy-param-mod %(dif)s.DIF resalloc reliable-n-flows true\n'
                        % {
                            'dif': dif
                        })
                ctrl_cmds.append(
                    'dif-policy-param-mod %(dif)s.DIF enrollment keepalive %(keepalive)s\n'
                    % {
                        'dif': dif,
                        'keepalive': self.keepalive
                    })

                for p in self.dif_policies[dif]:
                    if (len(p['nodes']) == 0 and dif not in vm['enrolling']) \
                            or (len(p['nodes']) > 0 and vmname in p.nodes):
                        ctrl_cmds.append(
                            'dif-policy-mod %(dif)s.DIF %(comp)s %(policy)s\n'
                            % {
                                'dif': dif,
                                'comp': p['path'],
                                'policy': p['ps']
                            })
                    if len(p['nodes']) == 0 or vmname in p.nodes:
                        for param in p['parms']:
                            pname, pvalue = param.split('=')

                            def replfun(m):
                                return "%s.%s.IPCP" % (
                                    dif, self.vms[m.group(1)]['id'])

                            pvalue = re.sub(r'\$([\w-]+)', replfun, pvalue)
                            ctrl_cmds.append(
                                'dif-policy-param-mod %(dif)s.DIF %(comp)s %(pname)s %(pvalue)s\n'
                                % {
                                    'dif': dif,
                                    'comp': p['path'],
                                    'pname': pname,
                                    'pvalue': pvalue
                                })
        return ctrl_cmds

    def compute_enrollments(self, vmname):
        # Carry out registrations following the DIF ordering,
        vm = self.vms[vmname]
        ctrl_cmds = []
        enroll_cmds = []
        appl_cmds = []
        for dif in self.dif_ordering:
            if dif in self.shims:
                # Shims don't register to other IPCPs
                continue

            if vmname not in self.difs[dif]:
                # Current node does not partecipate into the current DIF
                continue

            # Scan all the lower DIFs of the current DIF, for the current node
            for lower_dif in sorted(self.difs[dif][vmname]):
                vars_dict = {'dif': dif, 'id': vm['id'], 'lodif': lower_dif}
                ctrl_cmds.append(
                    'ipcp-register %(dif)s.%(id)s.IPCP %(lodif)s.DIF\n' %
                    vars_dict)
                del vars_dict

            if dif not in vm['enrolling']:
                vars_dict = {'dif': dif, 'id': vm['id']}
                ctrl_cmds.append(
                    'ipcp-enroller-enable %(dif)s.%(id)s.IPCP\n' % vars_dict)
                print("Node %s is the enrollment master for DIF %s" % (vmname,
                                                                       dif))
                del vars_dict

            vars_dict = {
                'echoname': 'rina-echo-async.%s' % vm['name'],
                'dif': dif,
                'perfname': 'rinaperf.%s' % vm['name']
            }
            if self.register:
                appl_cmds.append(
                    'rina-echo-async -z %(echoname)s -lw -d %(dif)s.DIF > rina-echo-async-%(dif)s.log 2>&1\n'
                    % vars_dict)
            if self.simulate:
                appl_cmds.append(
                    'rinaperf -z %(perfname)s -lw -d %(dif)s.DIF > rinaperf-%(dif)s.log 2>&1\n'
                    % vars_dict)
            del vars_dict

            enrollments_list = self.enrollments[dif] + self.lowerflowallocs[dif]
            for enrollment in enrollments_list:
                if enrollment['enrollee'] != vmname:
                    continue

                if enrollment in self.lowerflowallocs[dif]:
                    oper = 'lower-flow-alloc'
                else:
                    oper = 'enroll'

                vars_dict = {
                    'id': vm['id'],
                    'pvid': self.vms[enrollment['enroller']]['id'],
                    'vmname': vmname,
                    'oper': oper,
                    'dif': dif,
                    'ldif': enrollment['lower_dif']
                }
                cmd = 'ipcp-%(oper)s %(dif)s.%(id)s.IPCP %(dif)s.DIF %(ldif)s.DIF' % vars_dict
                if not self.broadcast_enrollment:
                    cmd += ' %(dif)s.%(pvid)s.IPCP' % vars_dict
                cmd += '\n'
                del vars_dict
                enroll_cmds.append(cmd)
        return (ctrl_cmds, enroll_cmds, appl_cmds)

    def realize_config(self):
        self.compute_order()
        self.assign_shim_ids()
        self.assign_vm_ids()
