#!/usr/bin/env python

#
# Author: Vincenzo Maffione <v.maffione@gmail.com>
#

import multiprocessing
import subprocess
import argparse
import json
import copy
import re
import os


def download_if_needed(locpath, url):
    try:
        import urllib.request
        downloader = urllib.request
    except:
        import urllib
        downloader = urllib

    if os.path.isfile(locpath):
        return

    print('Downloading %s ...' % url)
    fin = downloader.urlretrieve(url, locpath)
    print('... download complete')


def which(program):
    FNULL = open(os.devnull, 'w')
    retcode = subprocess.call(['sudo', 'which', program], stdout = FNULL,
                              stderr = subprocess.STDOUT)
    if retcode != 0:
        print('Fatal error: Cannot find "%s" program' % program)
        quit(1)


def join_keys(d1, d2):
    k = []
    for d in d1:
        k.append(d)
    for d in d2:
        k.append(d)
    return k


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

    if num == None or mask == None:
        return False

    return True


def prefix_prune_size(prefix):
    return prefix[:prefix.rfind('/')]


def num_to_ip(num, size, nomask):
    a = (num >> 24) & 0xFF
    b = (num >> 16) & 0xFF
    c = (num >> 8)  & 0xFF
    d = (num >> 0)  & 0xFF

    if nomask:
        return '%s.%s.%s.%s' % (a, b, c, d)

    return '%s.%s.%s.%s/%s' % (a, b, c, d, size)


def ip_in_prefix(prefix, i, nomask = False):
    num, mask, size = prefix_parse(prefix)
    if num == None or mask == None:
        return None

    if i & mask != 0:
        return None

    ip_num = num + i

    return num_to_ip(ip_num, size, nomask)


def netem_validate(netem_args):
    ret = True

    try:
        fdevnull = open(os.devnull, 'w')
        subprocess.check_call('sudo ip tuntap add mode tap name tapiratiprobe'.split())
        subprocess.check_call(('sudo tc qdisc add dev '\
                               'tapiratiprobe root netem %s'\
                                % netem_args).split(), stdout=fdevnull,
                                stderr=fdevnull)
        fdevnull.close()
    except:
        ret = False

    subprocess.call('sudo ip tuntap del mode tap name tapiratiprobe'.split())

    return ret

# For the sake of reproducibility we need a set with a deterministic pop()
# method. This one is basically a FIFO queue with logarithmic lookup cost.
class FrontierSet:
    def __init__(self, li = []):
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
            return None # We may throw an exception

        x = self.queue.pop(0)
        self.belong.remove(x)

        return x


def vm_get_mac(vmid, idx):
    return '00:0a:0a:%02x:%02x:%02x' % ((vmid >> 8) & 0xff, vmid & 0xff, idx)


description = "Python script to generate rlite deployments based on light VMs"
epilog = "2015-2016 Vincenzo Maffione <v.maffione@gmail.com>"

argparser = argparse.ArgumentParser(description = description,
                                    epilog = epilog)
argparser.add_argument('-c', '--conf',
                       help = "demo.conf configuration file", type = str,
                       default = 'demo.conf')
argparser.add_argument('--debug', action='store_true',
                       help = "When downloading images, select the debug one")
argparser.add_argument('-g', '--graphviz', action='store_true',
                       help = "Generate DIF graphs with graphviz")
argparser.add_argument('-m', '--memory',
                       help = "Amount of memory in megabytes", type = int,
                       default = 164) # 128 without KASAN
argparser.add_argument('--num-cpus',
                       help = "Number of vCPUs to give to each node", type = int,
                       default = 1)
argparser.add_argument('-p', '--base-port',
                       help = "Base SSH port to map nodes", type = int,
                       default = 2222)
argparser.add_argument('-e', '--enrollment-strategy',
                       help = "Minimal uses a spanning tree of each DIF",
                       type = str, choices = ['minimal', 'full-mesh'],
                       default = 'minimal')
argparser.add_argument('--ring',
                       help = "Use ring topology with variable number of nodes",
                       type = int)
argparser.add_argument('--verbosity',
                       help = "Set verbosity level for kernel and userspace",
                       choices = ['VERY', 'DBG', 'INFO', 'WARN', 'QUIET'],
                       default = 'DBG')
argparser.add_argument('-f', '--frontend',
                       help = "Choose which emulated NIC the nodes will use",
                       type = str, choices = ['virtio-net-pci', 'e1000'],
                       default = 'virtio-net-pci')
argparser.add_argument('--vhost', action='store_true',
                       help = "Use vhost acceleration for virtio-net frontend")
argparser.add_argument('-k', '--keepalive', default = 10,
                       help = "Neighbor keepalive timeout in seconds (0 to disable)", type = int)
argparser.add_argument('-N', '--reliable-n-flows', action='store_true',
                       help = "Use reliable N-flows if reliable N-1-flows are not available")
argparser.add_argument('-R', '--reliable-flows', action='store_true',
                       help = "Use reliable N-1-flows rather than unreliable ones")
argparser.add_argument('-A', '--addr-alloc-policy', type=str,
                        choices = ["auto", "manual"], default = "auto",
                       help = "Address allocation policy to be used for all DIFs")
argparser.add_argument('-r', '--register', action='store_true',
                       help = "Register rina-echo-async apps instances on each node")
argparser.add_argument('-i', '--image',
                       help = "qcow2 image for legacy mode", type = str,
                       default = '')
argparser.add_argument('--user',
                       help = "username for legacy mode", type = str,
                       default = 'root')
argparser.add_argument('--flavour',
                       help = "flavour to use for normal IPCPs", type = str,
                       default = '')
argparser.add_argument('--broadcast-enrollment', action='store_true',
                       help = "With broadcast enrollment, no neighbor "\
                              "is specified for the ipcp-enroll command, so "\
                              "that N-1 flow allocation is issued using the "\
                              "N-DIF name as destination application")
args = argparser.parse_args()


# Check we have what we need
which('brctl')
which('qemu-system-x86_64')

subprocess.call(['chmod', '0400', 'buildroot/buildroot_rsa'])

# Some variables that could become options
sshopts = '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
if not args.image:
    sshopts += '-o IdentityFile=buildroot/buildroot_rsa '
sudo = 'sudo' if args.image != '' else ''
vmimgpath = 'buildroot/rootfs.cpio'

flavour_suffix = ''
if args.flavour != '':
    flavour_suffix = '-' + args.flavour

imgprefix = "rlite.%s" % ('debug' if args.debug else 'prod',)
download_if_needed(vmimgpath, 'https://bitbucket.org/vmaffione/rina-images/downloads/%s.rootfs.cpio' % imgprefix)
download_if_needed('buildroot/bzImage', 'https://bitbucket.org/vmaffione/rina-images/downloads/%s.bzImage' % imgprefix)

# Possibly autogenerate ring topology
if args.ring != None and args.ring > 0:
    print("Ignoring %s, generating ring topology" % (args.conf,))
    fout = open('ring.conf', 'w')
    for i in range(args.ring):
        i_next = i + 1
        if i_next == args.ring:
            i_next = 0
        fout.write('eth b%(i)s 0Mbps m%(i)03d m%(inext)03d\n' % {'i': i+1,
                                                           'inext': i_next+1})
    for i in range(args.ring):
        i_prev = i - 1
        if i_prev < 0:
            i_prev = args.ring - 1
        fout.write('dif n m%(i)03d b%(i)s b%(iprev)s\n' % {'i': i+1,
                                                         'iprev': i_prev+1})
    fout.close()
    args.conf = 'ring.conf'


# Generated files needed by access.sh
fout = open('user', 'w')
fout.write(args.user)
fout.close()

fout = open('sshopts', 'w')
fout.write(sshopts)
fout.close()

############################# Parse demo.conf ##############################
fin = open(args.conf, 'r')

vms = dict()
shims = dict()
links = []
difs = dict()
enrollments = dict()
lowerflowallocs = dict()
dif_graphs = dict()
dif_policies = dict()
dns_mappings = dict()
netems = dict()
hostfwds = dict()

linecnt = 0

while 1:
    line = fin.readline()
    if line == '':
        break
    linecnt += 1

    line = line.replace('\n', '').strip()

    if line.startswith('#') or line == "":
        continue

    m = re.match(r'\s*eth\s+([\w-]+)\s+(\d+)([GMK])bps\s+(\w.*)$', line)
    if m:
        shim = m.group(1)
        speed = int(m.group(2))
        speed_unit = m.group(3).lower()
        vm_list = m.group(4).split()

        if shim in shims:
            print('Error: Line %d: shim %s already defined' \
                                            % (linecnt, shim))
            continue

        shims[shim] = {'name': shim, 'speed': speed,
                       'speed_unit': speed_unit, 'type': 'eth'}

        for vm in vm_list:
            if vm not in vms:
                vms[vm] = {'name': vm, 'ports': []}
            links.append((shim, vm))

        #for i in range(len(vm_list)-1):
        #    for j in range(i + 1, len(vm_list)):
        #        print(vm_list[i], vm_list[j])
        continue

    m = re.match(r'\s*udp4\s+([\w-]+)\s+(\w.*)$', line)
    if m:
        shim = m.group(1)
        members = m.group(2).split()

        if shim in shims:
            print('Error: Line %d: udp4 %s already defined' \
                                            % (linecnt, shim))
            continue

        shims[shim] = {'name': shim, 'type': 'udp4'}

        dns_mappings[shim] = dict()

        for member in members:
            vm, ip = member.split(':')

            if not prefix_is_valid(ip):
                print('Error: Line %d: ip %s is not valid' \
                                                % (linecnt, ip))
                continue

            if vm not in vms:
                vms[vm] = {'name': vm, 'ports': []}
            links.append((shim, vm))
            dns_mappings[shim][vm] = {'ip': ip}
        continue

    m = re.match(r'\s*dif\s+([\w-]+)\s+([\w-]+)\s+(\w.*)$', line)
    if m:
        dif = m.group(1)
        vm = m.group(2)
        dif_list = m.group(3).split()

        if vm not in vms:
            vms[vm] = {'name': vm, 'ports': []}

        if dif not in difs:
            difs[dif] = dict()

        if vm in sorted(difs[dif]):
            print('Error: Line %d: vm %s in dif %s already specified' \
                                            % (linecnt, vm, dif))
            continue

        difs[dif][vm] = dif_list

        continue

    m = re.match(r'\s*netem\s+([\w-]+)\s+([\w-]+)\s+(\w.*)$', line)
    if m:
        dif = m.group(1)
        vmname = m.group(2)
        netem_args = m.group(3)

        if dif not in netems:
            netems[dif] = dict()
        netems[dif][vmname] = {'args': netem_args, 'linecnt': linecnt}

        continue

    m = re.match(r'\s*hostfwd\s+([\w-]+)\s+((:?\d+:\d+\s*)+)$', line)
    if m:
        vmname = m.group(1)
        fwdlist = m.group(2).split()

        if vmname in hostfwds:
            print('Error: Line %d: hostfwd for %s already defined' \
                                            % (linecnt, vmname))
            continue

        # check for uniqueness of guest ports
        sg = set([int(x.split(':')[1]) for x in fwdlist])
        if 22 in sg or len(sg) != len(fwdlist):
            print('Error: Line %d: hostfwd for %s has conflicting mappings' \
                                            % (linecnt, vmname))
            continue

        hostfwds[vmname] = fwdlist

        continue

    m = re.match(r'\s*policy\s+(\w+)\s+(\*|(?:(?:\w+,)*\w+))\s+([*\w.-]+)\s+([\w-]+)((?:\s+[\w.-]+\s*=\s*[/\w.-]+)*)\s*$', line)
    if m:
        dif = m.group(1)
        nodes = m.group(2)
        path = m.group(3)
        ps = m.group(4)
        parms = list()
        if m.group(5) != None:
            parms_str = m.group(5).strip()
            if parms_str != '':
                parms = parms_str.split(' ')

        if dif not in dif_policies:
            dif_policies[dif] = []

        if nodes == '*':
            nodes = []
        else:
            nodes = nodes.split(',')

        dif_policies[dif].append({'path': path, 'nodes': nodes,
                                  'ps': ps, 'parms' : parms})
        continue

    # No match, spit a warning
    print('Warning: Line %d unrecognized and ignored' % linecnt)


fin.close()

# check for uniqueness of host ports
fwd_hports = set()
for vmname in hostfwds:
    for fwdr in hostfwds[vmname]:
        p = int(fwdr.split(':')[0])
        if p in fwd_hports:
            print('Error: hostfwds have mapping conflicts for port %d' % p)
            quit()
        fwd_hports.add(p)


boot_batch_size = max(1, multiprocessing.cpu_count() / 2)
wait_for_boot = 12  # in seconds
if len(vms) > 8:
    print("You want to run a lot of nodes, so it's better if I give "
          "each node some time to boot (since the boot is CPU-intensive)")

############ Compute registration/enrollment order for DIFs ###############

# Compute DIFs dependency graph, as both adjacency and incidence list.
difsdeps_adj = dict()
difsdeps_inc = dict()
for dif in sorted(difs):
    difsdeps_inc[dif] = set()
    difsdeps_adj[dif] = set()
for shim in shims:
    difsdeps_inc[shim] = set()
    difsdeps_adj[shim] = set()

for dif in sorted(difs):
    for vmname in sorted(difs[dif]):
        for lower_dif in sorted(difs[dif][vmname]):
            difsdeps_inc[dif].add(lower_dif)
            difsdeps_adj[lower_dif].add(dif)

# Kahn's algorithm below only needs per-node count of
# incident edges, so we compute these counts from the
# incidence list and drop the latter.
difsdeps_inc_cnt = dict()
for dif in difsdeps_inc:
    difsdeps_inc_cnt[dif] = len(difsdeps_inc[dif])
del difsdeps_inc

#print(difsdeps_adj)
#print(difsdeps_inc_inc)

# Run Kahn's algorithm to compute topological ordering on the DIFs graph.
frontier = FrontierSet()
dif_ordering = []
for dif in sorted(difsdeps_inc_cnt):
    if difsdeps_inc_cnt[dif] == 0:
        frontier.add(dif)

while not frontier.empty():
    cur = frontier.pop()
    dif_ordering.append(cur)
    for nxt in sorted(difsdeps_adj[cur]):
        difsdeps_inc_cnt[nxt] -= 1
        if difsdeps_inc_cnt[nxt] == 0:
            frontier.add(nxt)
    difsdeps_adj[cur] = set()

circular_set = [dif for dif in difsdeps_inc_cnt if difsdeps_inc_cnt[dif] != 0]
if len(circular_set):
    print("Fatal error: The specified DIFs topology has one or more"\
          "circular dependencies, involving the following"\
          " DIFs: %s" % circular_set)
    print("             DIFs dependency graph: %s" % difsdeps_adj);
    quit(1)

for dif in dif_ordering:
    if dif not in dif_policies:
        dif_policies[dif] = dict()


####################### Compute DIF graphs #######################
for dif in sorted(difs):
    neighsets = dict()
    dif_graphs[dif] = dict()
    first = None

    # For each N-1-DIF supporting this DIF, compute the set of nodes that
    # share such N-1-DIF. This set will be called the 'neighset' of
    # the N-1-DIF for the current DIF.

    for vmname in sorted(difs[dif]):
        dif_graphs[dif][vmname] = [] # init for later use
        if first == None: # pick any node for later use
            first = vmname
        first = vmname
        for lower_dif in sorted(difs[dif][vmname]):
            if lower_dif not in neighsets:
                neighsets[lower_dif] = []
            neighsets[lower_dif].append(vmname)

    # Build the graph, represented as adjacency list
    for lower_dif in neighsets:
        # Each neighset corresponds to a complete (sub)graph.
        for vm1 in neighsets[lower_dif]:
            for vm2 in neighsets[lower_dif]:
                if vm1 != vm2:
                    dif_graphs[dif][vm1].append((vm2, lower_dif))

    enrollments[dif] = []
    # To generate the list of enrollments, we simulate one,
    # using breadth-first trasversal.
    enrolled = set([first])
    frontier = FrontierSet([first])
    edges_covered = set()
    while not frontier.empty():
        cur = frontier.pop()
        for edge in dif_graphs[dif][cur]:
            if edge[0] not in enrolled:
                enrolled.add(edge[0])
                edges_covered.add((edge[0], cur))
                enrollments[dif].append({'enrollee': edge[0],
                                         'enroller': cur,
                                         'lower_dif': edge[1]})
                frontier.add(edge[0])

    lowerflowallocs[dif] = []
    if args.enrollment_strategy == 'full-mesh':
        for cur in dif_graphs[dif]:
            for edge in dif_graphs[dif][cur]:
                if cur < edge[0]:
                    if (cur, edge[0]) not in edges_covered and \
                            (edge[0], cur) not in edges_covered:
                        lowerflowallocs[dif].append({'enrollee': cur,
                                                     'enroller': edge[0],
                                                     'lower_dif': edge[1]})
                        edges_covered.add((cur, edge[0]))

    #print(neighsets)
    #print(dif_graphs[dif])

shim_id = 1
for shim in shims:
    enrollments[shim] = []
    lowerflowallocs[shim] = []
    shims[shim]['id'] = shim_id
    shim_id += 1


###################### Generate UP script ########################
fout = open('up.sh', 'w')

outs =  '#!/bin/bash\n'             \
        '\n'                        \
        'set -x\n'                  \
        '\n';

for shim in sorted(shims):
    outs += '(\n'                               \
            'sudo brctl addbr %(br)s\n'         \
            'sudo ip link set %(br)s up\n'      \
            ') &\n' % {'br': shim}

outs += 'wait\n'

for l in sorted(links):
    shim, vm = l
    idx = len(vms[vm]['ports']) + 1
    tap = '%s.%02x' % (vm, idx)

    outs += '(\n'                                           \
            'sudo ip tuntap add mode tap name %(tap)s\n'    \
            'sudo ip link set %(tap)s up\n'                 \
            'sudo brctl addif %(br)s %(tap)s\n'             \
                % {'tap': tap, 'br': shim}

    if shims[shim]['type'] == 'eth' and shims[shim]['speed'] > 0:
        speed = '%d%sbit' % (shims[shim]['speed'], shims[shim]['speed_unit'])
        if shim not in netems:
            netems[shim] = dict()
        if vm not in netems[shim]:
            netems[shim][vm] = {'args': '', 'linecnt': 0}

        # Rate limit the traffic transmitted on the TAP interface
        netems[shim][vm]['args'] += ' rate %s' % (speed,)

        # Rate limit the traffic transmitted on the TAP interface
        outs += 'sudo tc qdisc add dev %(tap)s handle 1: root '     \
                                'htb default 11\n'                  \
                'sudo tc class add dev %(tap)s parent 1: classid '  \
                                '1:1 htb rate 10gbit\n'             \
                'sudo tc class add dev %(tap)s parent 1:1 classid ' \
                                '1:11 htb rate %(speed)s\n'         \
                % {'tap': tap, 'speed': speed}

    outs += ') & \n'

    vms[vm]['ports'].append({'tap': tap, 'shim': shim, 'idx': idx,
                             'ip': dns_mappings[shim][vm]['ip'] if shim in dns_mappings else None})


outs += 'wait\n'

vmid = 1
budget = boot_batch_size

for vmname in sorted(vms):
    vm = vms[vmname]

    vm['id'] = vmid

    fwdp = args.base_port + vmid
    fwdc = fwdp + 10000
    mac = vm_get_mac(vmid, 99)

    vm['ssh'] = fwdp

    vars_dict = {'fwdp': fwdp, 'id': vmid, 'mac': mac,
                 'vmimgpath': vmimgpath, 'fwdc': fwdc,
                 'memory': args.memory, 'frontend': args.frontend,
                 'vmname': vmname, 'numcpus': args.num_cpus}

    hostfwdstr = 'hostfwd=tcp::%(fwdp)s-:22' % vars_dict
    if vmname in hostfwds:
        for fwdr in hostfwds[vmname]:
            hport, gport = fwdr.split(':')
            hostfwdstr += ',hostfwd=tcp::%s-:%s' % (hport, gport)

    vars_dict['hostfwdstr'] = hostfwdstr

    #'-serial tcp:127.0.0.1:%(fwdc)s,server,nowait '         \
    outs += 'qemu-system-x86_64 '
    if args.image != '': # standard buildroot image
        outs += args.image + ' -snapshot '
    else:
        outs += '-kernel buildroot/bzImage '                        \
                '-append "console=ttyS0" '                          \
                '-initrd %(vmimgpath)s ' % vars_dict
    outs += '-vga std '                                         \
            '-display none '                                    \
            '--enable-kvm '                                     \
            '-smp %(numcpus)s '                                 \
            '-m %(memory)sM '                                   \
            '-device %(frontend)s,mac=%(mac)s,netdev=mgmt '     \
            '-netdev user,id=mgmt,%(hostfwdstr)s '   \
            '-pidfile rina-%(id)s.pid '                         \
            '-serial file:%(vmname)s.log '                          \
                        % vars_dict

    del vars_dict

    for port in vm['ports']:
        tap = port['tap']
        mac = vm_get_mac(vmid, port['idx'])
        port['mac'] = mac

        outs += ''                                                      \
        '-device %(frontend)s,mac=%(mac)s,netdev=data%(idx)s '          \
        '-netdev tap,ifname=%(tap)s,id=data%(idx)s,script=no,'          \
        'downscript=no%(vhost)s '\
            % {'mac': mac, 'tap': tap, 'idx': port['idx'],
               'frontend': args.frontend,
               'vhost': ',vhost=on' if args.vhost else ''}

    outs += '&\n'

    budget -= 1
    if budget <= 0:
        outs += 'sleep %s\n' % wait_for_boot
        budget = boot_batch_size

    vmid += 1

# Compute DNS mappings
for vmname in sorted(vms):
    vm = vms[vmname]
    for dif in dif_ordering:
        if dif in shims or vmname not in difs[dif]:
            continue

        # Scan all the lower DIFs of the current DIF, for the current node
        for lower_dif in sorted(difs[dif][vmname]):
            if lower_dif in shims and shims[lower_dif]['type'] == 'udp4':
                vars_dict = {'dif': dif, 'id': vm['id']}
                dns_mappings[lower_dif][vmname]['name'] = '%(dif)s.%(id)s.IPCP:%(id)s' % vars_dict
                del vars_dict


# Generate per-VM setup script
outs += 'SUBSHELLS=""\n'
for vmname in sorted(vms):
    vm = vms[vmname]

    outs += '(\n'\
            'DONE=255\n'\
            'while [ $DONE != "0" ]; do\n'\
            '   ssh %(sshopts)s -p %(ssh)s %(username)s@localhost << \'ENDSSH\'\n'\
                    'set -x\n'\
                    'SUDO=%(sudo)s\n'\
                    '$SUDO hostname %(name)s\n'\
                    '\n'\
            '\n' % {'name': vm['name'], 'ssh': vm['ssh'], 'username': args.user,
                    'sshopts': sshopts, 'sudo': sudo}

    verbmap = {'QUIET': 1, 'WARN': 2, 'INFO': 3, 'DBG': 4, 'VERY': 5}

    # Load kernel modules
    outs +=         '$SUDO modprobe rlite verbosity=%(verbidx)s\n'\
                    '$SUDO modprobe rlite-shim-eth\n'\
                    '$SUDO modprobe rlite-shim-udp4\n'\
                    '$SUDO modprobe rlite-normal%(flsuf)s\n'\
                    '$SUDO chmod a+rwx /dev/rlite\n'\
                    '$SUDO chmod a+rwx /dev/rlite-io\n'\
                    '$SUDO mkdir -p /run/rlite\n'\
                    '$SUDO chmod -R a+rw /run/rlite\n'\
                    '$SUDO dmesg -n8\n'\
                    '\n'\
                    '$SUDO nohup rlite-uipcps -v %(verb)s -k %(keepalive)s '\
                                        '%(relnflows)s %(relflows)s '\
                                        '&> uipcp.log &\n'\
                        % {'verb': args.verbosity,
                           'verbidx': verbmap[args.verbosity],
                           'keepalive': args.keepalive,
                           'relnflows': '-N' if args.reliable_n_flows else '',
                           'relflows': '-R' if args.reliable_flows else '',
                           'flsuf': flavour_suffix}

    # Create and configure shim IPCPs
    for port in vm['ports']:
        shim = shims[port['shim']]
        vars_dict = {'mac': port['mac'], 'idx': port['idx'],
                     'shim': port['shim'], 'id': vm['id'],
                     'shimtype': shim['type']}
        outs +=     'PORT=$(mac2ifname %(mac)s)\n'\
                    '$SUDO ip link set $PORT up\n'\
                    '$SUDO rlite-ctl ipcp-create %(shim)s.%(id)s.IPCP:%(idx)s shim-%(shimtype)s %(shim)s.DIF\n'\
                    % vars_dict
        if shim['type'] == 'eth':
                outs += '$SUDO rlite-ctl ipcp-config %(shim)s.%(id)s.IPCP:%(idx)s netdev $PORT\n'\
                % vars_dict
        elif shim['type'] == 'udp4':
                outs += '$SUDO ip addr add %s dev $PORT\n' % (port['ip'])
        del vars_dict

    # Create normal IPCPs (it's handy to do it in topological DIF order)
    for dif in dif_ordering:
        if dif not in shims and vmname in difs[dif]:
            outs += '$SUDO rlite-ctl ipcp-create %(dif)s.%(id)s.IPCP:%(id)s normal%(flsuf)s %(dif)s.DIF\n'\
                                                                % {'dif': dif, 'id': vm['id'],
                                                                   'flsuf': flavour_suffix}
            if args.addr_alloc_policy == "manual":
                outs += '$SUDO rlite-ctl ipcp-config %(dif)s.%(id)s.IPCP:%(id)s address %(id)d\n'\
                                                                % {'dif': dif, 'id': vm['id']}
            for p in dif_policies[dif]:
                if len(p['nodes']) == 0 or vmname in p.nodes:
                    outs += '$SUDO rlite-ctl dif-policy-mod %(dif)s.DIF %(comp)s %(policy)s\n'\
                                % {'dif': dif, 'comp': p['path'], 'policy': p['ps']}

    # Update /etc/hosts file with DIF mappings
    for sh in dns_mappings:
        for nm in dns_mappings[sh]:
            outs += 'echo "%(ip)s %(name)s" >> /etc/hosts\n' \
                    % {'ip': prefix_prune_size(dns_mappings[sh][nm]['ip']), 'name': dns_mappings[sh][nm]['name']}

    # Carry out registrations following the DIF ordering
    for dif in dif_ordering:
        if dif in shims:
            # Shims don't register to other IPCPs
            continue

        if vmname not in difs[dif]:
            # Current node does not partecipate into the current DIF
            continue

        # Scan all the lower DIFs of the current DIF, for the current node
        for lower_dif in sorted(difs[dif][vmname]):
            vars_dict = {'dif': dif, 'id': vm['id'], 'lodif': lower_dif}
            outs += '$SUDO rlite-ctl ipcp-register %(dif)s.%(id)s.IPCP:%(id)s %(lodif)s.DIF\n'\
                        % vars_dict
            del vars_dict

        if args.register:
            outs += 'nohup rina-echo-async -z %(regname)s -l -d %(dif)s.DIF  &> rina-echo-async-%(dif)s.log &\n' \
                        % {'regname': 'rina-echo-async:%s' % (vm['name'],),
                           'dif': dif}

    outs +=         '\n'\
                    'sleep 1\n'\
                    'true\n'\
                'ENDSSH\n'\
            '   DONE=$?\n'\
            '   if [ $DONE != "0" ]; then\n'\
            '       sleep 1\n'\
            '   fi\n'\
            'done\n'\
            ') &\n'
    outs += 'SUBSHELLS="$SUBSHELLS $!"\n\n'

outs += 'wait $SUBSHELLS\n\n'

if len(dns_mappings) > 0:
    print("DNS mappings: %s" % (dns_mappings))


# Run the enrollment operations in an order which respect the dependencies
for dif in dif_ordering:
    enrollments_list = enrollments[dif] + lowerflowallocs[dif]
    for enrollment in enrollments_list:
        vm = vms[enrollment['enrollee']]

        if enrollment in lowerflowallocs[dif]:
            oper = 'lower-flow-alloc'
        else:
            oper = 'enroll'

        info = "%s %s to DIF %s through lower DIF %s" % (oper,
                    enrollment['enrollee'], dif, enrollment['lower_dif'])
        if not args.broadcast_enrollment:
            info += " [unicast to neighbor %s]" % enrollment['enroller']
        else:
            info += " [broadcast]"
        print(info)

        vars_dict = {'ssh': vm['ssh'], 'id': vm['id'],
                     'pvid': vms[enrollment['enroller']]['id'],
                     'username': args.user,
                     'vmname': vm['name'],
                     'dif': dif, 'ldif': enrollment['lower_dif'],
                     'sshopts': sshopts, 'sudo': sudo,
                     'oper': oper}

        outs += 'DONE=255\n'\
                'while [ $DONE != "0" ]; do\n'\
                '   ssh %(sshopts)s -p %(ssh)s %(username)s@localhost << \'ENDSSH\'\n'\
                'set -x\n'\
                'SUDO=%(sudo)s\n'\
                '$SUDO rlite-ctl ipcp-%(oper)s %(dif)s.%(id)s.IPCP:%(id)s %(dif)s.DIF '\
                        '%(ldif)s.DIF ' % vars_dict
        if not args.broadcast_enrollment:
            outs += '%(dif)s.%(pvid)s.IPCP:%(pvid)s\n' % vars_dict
        else:
            outs += '\n'
        outs += 'sleep 1\n'\
                'true\n'\
                'ENDSSH\n'\
                '   DONE=$?\n'\
                '   if [ $DONE != "0" ]; then\n'\
                '       sleep 1\n'\
                '   fi\n'\
                'done\n\n' % vars_dict


# Apply netem rules. For now this step is done after enrollment in order to
# avoid artificial packet losses during the enrollment phase. This would
# be a problem since shim DIFs do not provide reliable flows, and so some
# enrollments could fail. The enrollment procedure is retried for some
# times by the uipcps daemon (to cope with losses), but with many nodes
# the likelyhood of some enrollment failing many times is quite high.
for shim in shims:
    if shim not in netems:
        continue
    for vm in netems[shim]:
        if not netem_validate(netems[shim][vm]['args']):
            print('Warning: line %(linecnt)s is invalid and '\
                  'will be ignored' % netems[shim][vm])
            continue
        outs += 'sudo tc qdisc add dev %(tap)s root netem '\
                '%(args)s\n'\
                % {'tap': tap, 'args': netems[shim][vm]['args']}


fout.write(outs)

fout.close()

subprocess.call(['chmod', '+x', 'up.sh'])


###################### Generate DOWN script ########################
fout = open('down.sh', 'w')

outs =  '#!/bin/bash\n'             \
        '\n'                        \
        'set -x\n'                  \
        '\n'                        \
        'kill_qemu() {\n'           \
        '   PIDFILE=$1\n'           \
        '   PID=$(cat $PIDFILE)\n'  \
        '   if [ -n $PID ]; then\n' \
        '       kill $PID\n'        \
        '       while [ -n "$(ps -p $PID -o comm=)" ]; do\n'    \
        '           sleep 1\n'                                  \
        '       done\n'                                         \
        '   fi\n'                                               \
        '\n'                                                    \
        '   rm $PIDFILE\n'                                      \
        '}\n\n'

for vmname in sorted(vms):
    vm = vms[vmname]
    outs += 'kill_qemu rina-%(id)s.pid\n' % {'id': vm['id']}

outs += '\n'

for vmname in sorted(vms):
    vm = vms[vmname]
    for port in vm['ports']:
        tap = port['tap']
        shim = port['shim']

        outs += '(\n'                                           \
                'sudo brctl delif %(br)s %(tap)s\n'             \
                'sudo ip link set %(tap)s down\n'               \
                'sudo ip tuntap del mode tap name %(tap)s\n'    \
                ') &\n'                                         \
                    % {'tap': tap, 'br': shim}

outs += 'wait\n'

for shim in sorted(shims):
    outs += '(\n'                                   \
            'sudo ip link set %(br)s down\n'        \
            'sudo brctl delbr %(br)s\n'             \
            ') &\n' % {'br': shim}

outs += 'wait\n'

fout.write(outs)

fout.close()

subprocess.call(['chmod', '+x', 'down.sh'])


# Dump the mapping from nodes to SSH ports
fout = open('demo.map', 'w')
for vmname in sorted(vms):
    fout.write('%s %d\n' % (vmname, args.base_port + vms[vmname]['id']))
fout.close()


if args.graphviz:
    try:
        import pydot

        colors = ['red', 'green', 'blue', 'orange', 'yellow']
        fcolors = ['black', 'black', 'white', 'black', 'black']

        gvizg = pydot.Dot(graph_type = 'graph')
        i = 0
        for dif in sorted(difs):
            for vmname in dif_graphs[dif]:
                node = pydot.Node(dif + vmname,
                                  label = "%s(%s)" % (vmname, dif),
                                  style = "filled", fillcolor = colors[i],
                                  fontcolor = fcolors[i])
                gvizg.add_node(node)

            for vmname in dif_graphs[dif]:
                for (neigh, lower_dif) in dif_graphs[dif][vmname]:
                    if vmname > neigh:
                        # Use lexicographical filter to avoid duplicate edges
                        continue
                    edge = pydot.Edge(dif + vmname, dif + neigh,
                                      label = lower_dif)
                    gvizg.add_edge(edge)

            i += 1
            if i == len(colors):
                i = 0

        gvizg.write_png('difs.png')
    except:
        print("Warning: pydot module not installed, cannot produce DIF "\
              "graphs images")


###### Generate echo script for automatic testing ######
if args.register:
    fout = open('echo.sh', 'w')

    outs =  '#!/bin/bash\n'             \
            '\n'                        \
            '#set -x\n'

    # For each DIF
    for dif in dif_ordering:
        if dif in shims or len(difs[dif]) == 0:
            continue

        # Select a pivot node
        pivot = sorted(difs[dif])[0]
        outs += 'echo "Use \"%(pivot)s\" as a pivot for DIF %(dif)s"\n'\
            'DONE=255\n'\
            'while [ $DONE != "0" ]; do\n'\
            '   ssh %(sshopts)s -p %(ssh)s %(username)s@localhost << \'ENDSSH\'\n'\
                    '#set -x\n' % {'sshopts': sshopts, 'username': args.user,
                                  'ssh': vms[pivot]['ssh'], 'pivot': pivot,
                                  'dif': dif}

        for vmname in sorted(difs[dif]):
            outs += 'echo "%(pivot)s --> %(vmname)s"\n'\
                    'rina-echo-async -z rina-echo-async:%(vmname)s -d %(dif)s.DIF\n' \
                    '[ "$?" == "0" ] || echo "Failed to reach %(vmname)s ' \
                        'in DIF %(dif)s"\n'\
                        % {'vmname': vmname, 'dif': dif, 'pivot': pivot}

        outs +=      'true\n'\
                'ENDSSH\n'\
            '   DONE=$?\n'\
            '   if [ $DONE != "0" ]; then\n'\
            '       sleep 1\n'\
            '   fi\n'\
            'done\n\n'

    fout.write(outs)
    fout.close()
    subprocess.call(['chmod', '+x', 'echo.sh'])
