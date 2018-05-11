#!/usr/bin/env python

#
# Author: Vincenzo Maffione <v.maffione@gmail.com>
#

import multiprocessing
import subprocess
import argparse
import os

from libdemo import Demo, prefix_parse


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


# Wrapper for the 'which' command, to check a program exists on
# the local machine.
def which(program, sudo = False):
    FNULL = open(os.devnull, 'w')
    cmd = ['which', program]
    if sudo:
        cmd = ['sudo'] + cmd
    retcode = subprocess.call(cmd, stdout = FNULL,
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
        subprocess.check_call('sudo ip tuntap add mode tap name tapbrobe'.split())
        subprocess.check_call(('sudo tc qdisc add dev '\
                               'tapbrobe root netem %s'\
                                % netem_args).split(), stdout=fdevnull,
                                stderr=fdevnull)
        fdevnull.close()
    except:
        ret = False

    subprocess.call('sudo ip tuntap del mode tap name tapbrobe'.split())

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
            return level # not worth going on

        while not frontier.empty():
            cur = frontier.pop()
            for (neigh, lower_dif) in graph[cur]:
                if neigh not in marked:
                    new_frontier.add(neigh)
                    marked.add(neigh)
        frontier = new_frontier

    return level


def access_prologue(args, vm, outs, escape = True):
    token = None
    eof = '\'EOI\'' if escape else 'EOI'
    if args.namespaces:
        scriptname = '.%s.initscript' % vm['name']
        outs += 'cat > %(script)s << %(eof)s\n' % {'script': scriptname, 'eof': eof}
        outs += '#!/bin/bash\n'
        token = scriptname
    else:
        outs += 'DONE=255\n'\
                'while [ $DONE != "0" ]; do\n'\
                '   ssh -T %(sshopts)s -p %(ssh)s %(username)s@localhost << %(eof)s\n'\
                % {'ssh': vm['ssh'], 'username': args.user, 'eof': eof,
                  'sshopts': args.sshopts}
    return outs, token

def access_epilogue(args, vm, outs, token):
    if args.namespaces:
        scriptname = token
        outs += 'EOI\n'\
                'chmod +x %(script)s\n'\
                'sudo ip netns exec %(nsname)s bash %(script)s\n'\
                'rm %(script)s\n'\
                    % {'script': scriptname, 'nsname': vm['nsname']}
    else:
        outs +=     ''\
                    'sleep 1\n'\
                    'true\n'\
                'EOI\n'\
            '   DONE=$?\n'\
            '   if [ $DONE != "0" ]; then\n'\
            '       sleep 1\n'\
            '   fi\n'\
            'done\n'
    return outs


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
argparser.add_argument('--valgrind', action='store_true',
                       help = "Run the uipcps daemon under valgrind (e.g. to catch SIGSEGV)")
argparser.add_argument('-m', '--memory',
                       help = "Amount of memory in megabytes", type = int,
                       default = 164) # 128 without KASAN
argparser.add_argument('--wait-for-boot',
                       help = "Number of seconds to wait between the boot "\
                              "of a batch of nodes and the next one",
                       type = int, default = 10) # 128 without KASAN
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
argparser.add_argument('--ring', type = int,
                       help = "Use ring topology with variable number of nodes")
argparser.add_argument('--tree', type = int,
                       help = "Use tree topology with variable number of nodes")
argparser.add_argument('--resilient-tree', action='store_true',
                       help = "Use resilient tree topology (connected siblings)")
argparser.add_argument('--tree-cardinality', type = int, default = 3,
                       help = "Number of children per node for the tree topology")
argparser.add_argument('--verbosity',
                       help = "Set verbosity level for kernel and userspace",
                       choices = ['VERY', 'DBG', 'INFO', 'WARN', 'QUIET'],
                       default = 'DBG')
argparser.add_argument('-f', '--frontend',
                       help = "Choose which emulated NIC the nodes will use",
                       type = str, choices = ['virtio-net-pci', 'e1000'],
                       default = 'virtio-net-pci')
argparser.add_argument('-b', '--backend',
                       help = "Choose network backend used by nodes",
                       type = str, choices = ['tap', 'udp'], default = None)
argparser.add_argument('--vhost', action='store_true',
                       help = "Use vhost acceleration for virtio-net frontend")
argparser.add_argument('-k', '--keepalive', default = 20,
                       help = "Neighbor keepalive timeout in seconds (0 to disable)", type = int)
argparser.add_argument('-N', '--reliable-n-flows', action='store_true',
                       help = "Use reliable N-flows if reliable N-1-flows are not available")
argparser.add_argument('-R', '--reliable-flows', action='store_true',
                       help = "If possible, use dedicated reliable N-1-flows "
                              "for management traffic rather than reusing "
                              "kernel-bound unreliable N-1 flows")
argparser.add_argument('-A', '--addr-alloc-policy', type=str,
                        choices = ["distributed", "static", "centralized-fault-tolerant"], default = "distributed",
                       help = "Address allocation policy to be used for all DIFs")
argparser.add_argument('-r', '--register', action='store_true',
                       help = "Register rina-echo-async apps instances on each node")
argparser.add_argument('-s', '--simulate', action='store_true',
                       help = "Simulate network load using the rlite-rand-clients on each node")
argparser.add_argument('-T', '--rand-period', default = 1, type = int,
                       help = "Average time between two rinaperf spawns")
argparser.add_argument('-D', '--rand-duration', default = 8, type = int,
                       help = "Average duration of a rinaperf client")
argparser.add_argument('-M', '--rand-max', default = 40, type = int,
                       help = "Max number of spawned of rinaperf client")
argparser.add_argument('-I', '--rand-interval', default = 1000, type = int,
                       help = "Min inter-packet interval for rinaperf clients")
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
argparser.add_argument('--enrollment-order',
                       help = "Sequential vs parallel enrollment",
                       type = str, choices = ['sequential', 'parallel'],
                       default = None)
argparser.add_argument('--dump-initscripts',
                       help = "Dump an initscript for each machine",
                       action = "store_true", default = False);
argparser.add_argument('--csum',
                       help = "Use checksums for all the DIFs",
                       type = str, choices = ['inet', 'none'],
                       default = 'none')
argparser.add_argument('-C', '--namespaces', action='store_true',
                       help = "Implement each node as a network namespace rather than "\
                              "a Virtual Machine")
args = argparser.parse_args()


# Check we have what we need
if not args.namespaces:
    which('qemu-system-x86_64')

subprocess.call(['chmod', '0400', 'buildroot/buildroot_rsa'])

# Some variables that could become options
args.sshopts = '-q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
if not args.image:
    args.sshopts += '-o IdentityFile=buildroot/buildroot_rsa '
sudo = 'sudo' if args.image != '' and not args.namespaces else ''
vmimgpath = 'buildroot/rootfs.cpio'

flavour_suffix = ''
if args.flavour != '':
    flavour_suffix = '-' + args.flavour

if not args.namespaces:
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


# Possibly autogenerate multi-layer tree topology
if args.tree != None and args.tree > 0:
    print("Ignoring %s, generating tree topology" % (args.conf,))
    fout = open('tree.conf', 'w')

    prev_level = [1]
    next_level = []
    cur_node_idx = 2
    n = args.tree - 1
    neighs = dict()
    while n > 0:
        for p in prev_level:
            for j in range(args.tree_cardinality):
                next_level.append(cur_node_idx)
                if p not in neighs:
                    neighs[p] = []
                neighs[p].append(cur_node_idx)
                if cur_node_idx not in neighs:
                    neighs[cur_node_idx] = []
                neighs[cur_node_idx].append(p)
                if args.resilient_tree:
                    if j > 0:
                        neighs[cur_node_idx].append(cur_node_idx-1)
                    if j < args.tree_cardinality-1:
                        neighs[cur_node_idx].append(cur_node_idx+1)
                cur_node_idx += 1
                n -= 1
                if n == 0:
                    break
            if n == 0:
                break
        prev_level = next_level
        next_level = []

    bnames = dict()
    bidx = 1
    for p in neighs:
        for x in neighs[p]:
            if p < x:
                fout.write('eth b%(br)s 0Mbps m%(p)03d m%(x)03d\n' \
                           % {'p': p, 'x': x, 'br': bidx})
                bnames[(p,x)] = bnames[(x,p)] = bidx
                bidx += 1

    for p in neighs:
        lstring = ''
        for x in neighs[p]:
            lstring += 'b%s ' % bnames[(p,x)]
        fout.write('dif n m%03d %s\n' % (p, lstring))
    fout.close()
    args.conf = 'tree.conf'

# Generate access.sh script
fout = open('access.sh', 'w')
outs = '#!/bin/bash\n'\
       'MACHINE_ID=$1\n'\
       'if [ "$MACHINE_ID" == "" ]; then\n'\
       '    echo "usage: $0 NODE_NAME"\n'\
       '    exit 255\n'\
       'fi\n\n'
if args.namespaces:
    outs += 'sudo ip netns exec ns${MACHINE_ID} bash\n'
else:
    outs += 'USER=%s\n' % args.user
    outs += 'SSHOPTS=%s\n' % args.sshopts
    outs += ''\
            'SSH_PORT=$(grep "\\<${MACHINE_ID}\\>" demo.map | awk \'{print $2}\')\n'\
            'if [ "$SSH_PORT" == "" ]; then\n'\
            '    echo "Error: Node ${MACHINE_ID} unknown"\n'\
            '    exit 255\n'\
            'fi\n\n'\
            'echo "Accessing buildroot VM ${MACHINE_ID}"\n'\
            'ssh $SSHOPTS -p ${SSH_PORT} $USER@localhost\n'
fout.write(outs)
fout.close()
subprocess.call(['chmod', '+x', 'access.sh'])

demo = Demo(flavour_suffix=flavour_suffix,
            addr_alloc_policy=args.addr_alloc_policy,
            reliable_flows=args.reliable_flows,
            reliable_n_flows=args.reliable_n_flows,
            keepalive=args.keepalive,
            register=args.register,
            simulate=args.simulate,
            broadcast_enrollment=args.broadcast_enrollment,
            enrollment_strategy=args.enrollment_strategy,
            csum = args.csum)

demo.parse_config(args.conf)

if args.namespaces:
    boot_batch_size = 100000  # infinite batch size
    args.backend = 'veth'
else:
    boot_batch_size = max(1, multiprocessing.cpu_count() / 2)
    if len(demo.vms) > boot_batch_size:
        print("You want to run a lot of nodes, so it's better if I give "
              "each node some time to boot (since the boot is CPU-intensive)")

VMTHRESH = 10
if not args.backend:
    args.backend = 'tap' if len(demo.vms) <= VMTHRESH else 'udp'

if not args.enrollment_order:
    args.enrollment_order = 'sequential' if len(demo.vms) <= VMTHRESH else 'parallel'

demo.enrollment_order = args.enrollment_order
demo.realize_config()

###################### Generate UP script ########################
fout = open('up.sh', 'w')

outs =  '#!/bin/bash\n'             \
        '\n'                        \
        'set -x\n'                  \
        '\n./clean.sh\n\n';

if args.backend == 'tap':
    for shim in sorted(demo.shims):
        outs += '(\n'                               \
                'sudo ip link add name %(br)s type bridge\n'\
                'sudo ip link set %(br)s up\n'      \
                ') &\n' % {'br': shim}
    outs += 'wait\n'
elif args.backend in ['udp', 'veth']:
    for shim in sorted(demo.shims):
        if len(demo.shims[shim]['vms']) != 2:
            print('Error: UDP backend only supports peer-to-peer links')
            quit()

udp_idx = args.base_port
udp_map = dict()

if args.namespaces:
    for shname in sorted(demo.shims):
        shim = demo.shims[shname]
        assert(len(shim['vms']) == 2)
        vm0 = shim['vms'][0]
        vm1 = shim['vms'][1]
        veth0 = '%s.%s' % (shim['name'][:8], vm0[:7])
        veth1 = '%s.%s' % (shim['name'][:8], vm1[:7])
        outs += '(\n'\
                'sudo ip link add %s type veth peer name %s\n'\
                ') &\n'\
            % (veth0, veth1)
        idx0 = len(demo.vms[vm0]['ports']) + 1
        idx1 = len(demo.vms[vm1]['ports']) + 1
        demo.vms[vm0]['ports'].append({'veth': veth0, 'shim': shname, 'idx': idx0})
        demo.vms[vm1]['ports'].append({'veth': veth1, 'shim': shname, 'idx': idx1})
    outs += 'wait\n'
else:
    for l in sorted(demo.links):
        shim, vm = l
        idx = len(demo.vms[vm]['ports']) + 1
        tap = '%s.%02x' % (vm, idx)

        # Assign UDP ports
        if shim not in udp_map:
            udp_map[shim] = dict()
        for shvm in demo.shims[shim]['vms']:
            if shvm not in udp_map[shim]:
                udp_map[shim][shvm] = udp_idx
                udp_idx += 1
            if shvm == vm:
                udp_local_port = udp_map[shim][shvm]
            else:
                udp_remote_port = udp_map[shim][shvm]

        if args.backend == 'tap':
            outs += '(\n'                                           \
                    'sudo ip tuntap add mode tap name %(tap)s\n'    \
                    'sudo ip link set %(tap)s up\n'                 \
                    'sudo ip link set %(tap)s master %(br)s\n'             \
                        % {'tap': tap, 'br': shim}

            if demo.shims[shim]['type'] == 'eth' and demo.shims[shim]['speed'] > 0:
                speed = '%d%sbit' % (demo.shims[shim]['speed'], demo.shims[shim]['speed_unit'])

                # Rate limit the traffic transmitted on the TAP interface
                outs += 'sudo tc qdisc add dev %(tap)s handle 1: root '     \
                                        'htb default 11\n'                  \
                        'sudo tc class add dev %(tap)s parent 1: classid '  \
                                        '1:1 htb rate 10gbit\n'             \
                        'sudo tc class add dev %(tap)s parent 1:1 classid ' \
                                        '1:11 htb rate %(speed)s\n'         \
                        % {'tap': tap, 'speed': speed}

            outs += ') &\n'

        demo.vms[vm]['ports'].append({'tap': tap, 'shim': shim, 'idx': idx,
                             'ip': demo.dns_mappings[shim][vm]['ip'] if shim in
                             demo.dns_mappings else None,
                             'udpl': udp_local_port, 'udpr': udp_remote_port,
                            })

if args.backend == 'tap':
    outs += 'wait\n'


verbmap = {'QUIET': 1, 'WARN': 2, 'INFO': 3, 'DBG': 4, 'VERY': 5}

if args.namespaces:
    # Load the modules only once
    outs += ''\
        'sudo modprobe rlite verbosity=%(verbidx)s\n'\
        'sudo modprobe rlite-shim-eth\n'\
        'sudo modprobe rlite-shim-udp4\n'\
        'sudo modprobe rlite-shim-loopback\n'\
        'sudo modprobe rlite-normal%(flsuf)s\n'\
        'sudo chmod a+rwx /dev/rlite\n'\
        'sudo chmod a+rwx /dev/rlite-io\n'\
        'sudo mkdir -p /run/rlite\n'\
        'sudo chmod -R a+rw /run/rlite\n'\
        'sudo dmesg -n8\n'\
            % {'verb': args.verbosity,
               'verbidx': verbmap[args.verbosity],
               'flsuf': flavour_suffix}


budget = boot_batch_size
for vmname in sorted(demo.vms):
    vm = demo.vms[vmname]
    vmid = vm['id']

    if args.namespaces:
        vm['nsname'] = 'ns%s' % vmname
        outs += '(\n'\
                'sudo ip netns add %(nsname)s\n'\
                'sudo ip netns exec %(nsname)s ip link set lo up\n'\
                  % {'nsname': vm['nsname']}
        for port in vm['ports']:
            outs += 'sudo ip link set %s netns %s\n'\
                % (port['veth'], vm['nsname'])
        outs += ') &\n'
    else:
        fwdp = args.base_port + vmid
        fwdc = fwdp + 10000
        mac = vm_get_mac(vmid, 99)

        vm['ssh'] = fwdp

        vars_dict = {'fwdp': fwdp, 'id': vmid, 'mac': mac,
                     'vmimgpath': vmimgpath, 'fwdc': fwdc,
                     'memory': args.memory, 'frontend': args.frontend,
                     'vmname': vmname, 'numcpus': args.num_cpus}

        hostfwdstr = 'hostfwd=tcp::%(fwdp)s-:22' % vars_dict
        if vmname in demo.hostfwds:
            for fwdr in demo.hostfwds[vmname]:
                hport, gport = fwdr.split(':')
                hostfwdstr += ',hostfwd=tcp::%s-:%s' % (hport, gport)

        vars_dict['hostfwdstr'] = hostfwdstr

        # '-serial tcp:127.0.0.1:%(fwdc)s,server,nowait '
        outs += 'qemu-system-x86_64 '
        if args.image != '':  # standard buildroot image
            outs += args.image + ' -snapshot '
        else:
            outs += '-kernel buildroot/bzImage '                    \
                    '-append "console=ttyS0" '                      \
                    '-initrd %(vmimgpath)s ' % vars_dict
        outs += '-vga std '                                         \
                '-display none '                                    \
                '--enable-kvm '                                     \
                '-smp %(numcpus)s '                                 \
                '-m %(memory)sM '                                   \
                '-device %(frontend)s,mac=%(mac)s,netdev=mgmt '     \
                '-netdev user,id=mgmt,%(hostfwdstr)s '              \
                '-pidfile rina-%(id)s.pid '                         \
                '-serial file:%(vmname)s.log '                      \
                % vars_dict

        del vars_dict

        for port in vm['ports']:
            tap = port['tap']
            mac = vm_get_mac(vmid, port['idx'])
            port['mac'] = mac

            vars_dict = {'mac': mac, 'idx': port['idx'], 'frontend': args.frontend}

            outs += '-device %(frontend)s,mac=%(mac)s,netdev=data%(idx)s ' % vars_dict
            if args.backend == 'tap':
                vars_dict['tap'] = tap
                vars_dict['vhost'] = ',vhost=on' if args.vhost else ''
                outs += '-netdev tap,ifname=%(tap)s,id=data%(idx)s,script=no,'  \
                        'downscript=no%(vhost)s ' % vars_dict
            elif args.backend == 'udp':
                vars_dict['udpl'] = port['udpl']
                vars_dict['udpr'] = port['udpr']
                outs += '-netdev socket,localaddr=127.0.0.1:%(udpl)s,'\
                        'udp=127.0.0.1:%(udpr)d,id=data%(idx)s ' % vars_dict
            else:
                assert(False)
            del vars_dict

        outs += '&\n'

    budget -= 1
    if budget <= 0:
        outs += 'sleep %s\n' % args.wait_for_boot
        budget = boot_batch_size

if args.namespaces:
    outs += 'wait\n'

# Compute DNS mappings
for vmname in sorted(demo.vms):
    vm = demo.vms[vmname]
    for dif in demo.dif_ordering:
        if dif in demo.shims or vmname not in demo.difs[dif]:
            continue

        # Scan all the lower DIFs of the current DIF, for the current node
        for lower_dif in sorted(demo.difs[dif][vmname]):
            if lower_dif in demo.shims and demo.shims[lower_dif]['type'] == 'udp4':
                vars_dict = {'dif': dif, 'id': vm['id'], 'vmname': vmname}
                demo.dns_mappings[lower_dif][vmname]['name'] = '%(dif)s.%(vmname)s.IPCP' % vars_dict
                del vars_dict


# Generate per-VM setup script
vm_conf_batch = 20
vm_conf_count = 0
outs += 'SUBSHELLS=""\n'
for vmname in sorted(demo.vms):
    vm = demo.vms[vmname]

    if vm_conf_count == vm_conf_batch:
            outs += 'wait $SUBSHELLS\n\n'
            vm_conf_count = 0
            outs += 'SUBSHELLS=""\n'

    outs += '(\n'
    outs, token = access_prologue(args, vm, outs)

    outs +=         'set -x\n'\
                    'SUDO=%(sudo)s\n' % {'sudo': sudo}
    if not args.namespaces:
        outs +=     '$SUDO hostname %(name)s\n' % {'name': vm['name']}

        # Load kernel modules
        outs +=     '$SUDO modprobe rlite verbosity=%(verbidx)s\n'\
                    '$SUDO modprobe rlite-shim-eth\n'\
                    '$SUDO modprobe rlite-shim-udp4\n'\
                    '$SUDO modprobe rlite-normal%(flsuf)s\n'\
                    '$SUDO chmod a+rwx /dev/rlite\n'\
                    '$SUDO chmod a+rwx /dev/rlite-io\n'\
                    '$SUDO mkdir -p /run/rlite\n'\
                    '$SUDO chmod -R a+rw /run/rlite\n'\
                    '$SUDO dmesg -n8\n'\
                        % {'verbidx': verbmap[args.verbosity],
                           'flsuf': flavour_suffix}

    outs +=         '$SUDO %(valgrind)s rlite-uipcps -d -v %(verb)s '\
                            '> uipcp.%(vmname)s.log 2>&1\n'\
                        % {'verb': args.verbosity,
                           'vmname': vmname,
                           'valgrind': 'valgrind' if args.valgrind else ''}

    ctrl_cmds = []

    # Create and configure shim IPCPs
    pouts, pctrl_cmds = demo.compute_shim_ipcps(vm, not args.namespaces)
    outs += pouts
    ctrl_cmds += pctrl_cmds

    # Create normal IPCPs (it's handy to do it in topological DIF order)
    ctrl_cmds += demo.compute_normal_ipcps(vmname)

    # Update /etc/hosts file with DIF mappings
    for sh in demo.dns_mappings:
        outs += '$SUDO rm /etc/hosts\n'
        for nm in demo.dns_mappings[sh]:
            outs += "$SUDO sh -c 'echo \"%(ip)s %(name)s\" >> /etc/hosts'\n" \
                    % {'ip': prefix_prune_size(demo.dns_mappings[sh][nm]['ip']),
                            'name': demo.dns_mappings[sh][nm]['name']}

    # Carry out registrations following the DIF ordering,
    pctrl_cmds, enroll_cmds, appl_cmds = demo.compute_enrollments(vmname)
    ctrl_cmds += pctrl_cmds

    if args.dump_initscripts:
        initscript_name = vm['name'] + '.initscript'
        initscript = open(initscript_name, 'w')
        initscript_outs = ''
        for cmd in ctrl_cmds:
            initscript_outs += cmd
        for cmd in enroll_cmds:
            initscript_outs += cmd
        initscript.write(initscript_outs)
        initscript.close()

    # Generate /etc/rina/initscript
    node_config_file = 'node-config.%s.initscript' % vmname
    outs += 'cat > %s <<EOF\n' % node_config_file
    for cmd in ctrl_cmds:
        outs += cmd
    outs += 'EOF\n'

    if args.enrollment_order == 'parallel':
        # Add enrollments to the initscript only when parallel enrollment
        # is used.
        outs += 'cat >> %s <<EOF\n' % node_config_file
        for cmd in enroll_cmds:
            outs += cmd
        outs += 'EOF\n'

    # Run rlite-node-config
    rlnc_options = ''
    if len(demo.vms) > 400:
        rlnc_options += ' --one-shot'
    outs += '$SUDO nohup rlite-node-config -v -d -s %s %s > rlite-node-config.%s.log 2>&1\n'\
            % (node_config_file, rlnc_options, vmname)

    # Configure netem rules inside the nodes, including htb rate limiting
    outs += demo.compute_netem_rules(vm)

    # Run applications after rlite-node-config, so that we are sure the IPCPs
    # are there (non-enrollment commands are run before turning into a daemon).
    for cmd in appl_cmds:
        outs += cmd

    # Run rlite-rand clients
    if args.simulate:
        outs += 'nohup rlite-rand-clients -T %(randperiod)s -D %(randdur)s -M %(randmax)s -I %(randintv)s '\
                    ' > rlite-rand-clients.log 2>&1 &\n' % \
                    {'randperiod': args.rand_period,
                     'randdur': args.rand_duration,
                     'randmax': args.rand_max,
                     'randintv': args.rand_interval }

    outs = access_epilogue(args, vm, outs, token)

    outs += ') &\n'\
            'SUBSHELLS="$SUBSHELLS $!"\n\n'
    vm_conf_count += 1

if vm_conf_count > 0:
    outs += 'wait $SUBSHELLS\n\n'


if len(demo.dns_mappings) > 0:
    print("DNS mappings: %s" % (demo.dns_mappings))

if args.enrollment_order == 'sequential':
    # Run the enrollment operations in an order which respect the dependencies
    for dif in demo.dif_ordering:
        enrollments_list = demo.enrollments[dif] + demo.lowerflowallocs[dif]
        for enrollment in enrollments_list:
            vm = demo.vms[enrollment['enrollee']]

            if enrollment in demo.lowerflowallocs[dif]:
                oper = 'lower-flow-alloc'
            else:
                oper = 'enroll-retry'

            vars_dict = {'id': vm['id'],
                         'pvname': demo.vms[enrollment['enroller']]['name'],
                         'vmname': vm['name'],
                         'dif': dif, 'ldif': enrollment['lower_dif'],
                          'sudo': sudo,
                         'oper': oper}

            outs, token = access_prologue(args, vm, outs)

            outs += 'set -x\n'\
                    'SUDO=%(sudo)s\n'\
                    '$SUDO rlite-ctl ipcp-%(oper)s %(dif)s.%(vmname)s.IPCP %(dif)s.DIF '\
                            '%(ldif)s.DIF ' % vars_dict
            if not demo.broadcast_enrollment:
                outs += '%(dif)s.%(pvname)s.IPCP\n' % vars_dict
            else:
                outs += '\n'

            outs = access_epilogue(args, vm, outs, token)

# Just for debugging
for dif in demo.dif_ordering:
    enrollments_list = demo.enrollments[dif] + demo.lowerflowallocs[dif]
    for enrollment in enrollments_list:
        vm = demo.vms[enrollment['enrollee']]

        if enrollment in demo.lowerflowallocs[dif]:
            oper = 'lower-flow-alloc'
        else:
            oper = 'enroll'

        info = "%s %s to DIF %s through lower DIF %s" % (oper,
                    enrollment['enrollee'], dif, enrollment['lower_dif'])
        if not demo.broadcast_enrollment:
            info += " [unicast to neighbor %s]" % enrollment['enroller']
        else:
            info += " [broadcast]"
        print(info)


fout.write(outs)

fout.close()

subprocess.call(['chmod', '+x', 'up.sh'])


###################### Generate DOWN script ########################
fout = open('down.sh', 'w')

outs =  '#!/bin/bash\n'             \
        '\n'                        \
        'set -x\n\n'

if not args.namespaces:
    outs += ''\
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
    for vmname in sorted(demo.vms):
        vm = demo.vms[vmname]
        outs += '( kill_qemu rina-%(id)s.pid ) &\n' % {'id': vm['id']}

    outs += 'wait\n'

if args.namespaces:
    # Remove all the namespaces (this also deletes the veths)
    for vmname in sorted(demo.vms):
        vm = demo.vms[vmname]
        outs += '(\n'\
                'sudo ip netns exec %(nsname)s rlite-ctl reset\n'\
                'sudo ip netns del %(nsname)s\n'\
                ') &\n' % {'nsname': vm['nsname']}
    outs += 'wait\n'

    # Kill the daemons and unload the modules
    outs += 'sleep 1\n'\
            'sudo pkill -f -9 rina-echo-async\n'\
            'sudo pkill -f -9 rinaperf\n'\
            'sudo pkill -f -9 rlite-node-config\n'\
            'sudo pkill -f -9 rlite-uipcps\n'\
            'sleep 1\n'\
            'sudo rmmod rlite-shim-loopback\n'\
            'sudo rmmod rlite-normal%(flsuf)s\n'\
            'sudo rmmod rlite-shim-eth\n'\
            'sudo rmmod rlite-shim-udp4\n'\
            'sudo rmmod rlite\n' % {'flsuf': flavour_suffix}

elif args.backend == 'tap':
    for vmname in sorted(demo.vms):
        vm = demo.vms[vmname]
        for port in vm['ports']:
            tap = port['tap']
            shim = port['shim']

            outs += '(\n'                                           \
                    'sudo ip link set %(tap)s nomaster\n'           \
                    'sudo ip link set %(tap)s down\n'               \
                    'sudo ip tuntap del mode tap name %(tap)s\n'    \
                    ') &\n'                                         \
                        % {'tap': tap, 'br': shim}
    outs += 'wait\n'

    for shim in sorted(demo.shims):
        outs += '(\n'                                   \
                'sudo ip link set %(br)s down\n'        \
                'sudo ip link del %(br)s type bridge\n' \
                ') &\n' % {'br': shim}
    outs += 'wait\n'

fout.write(outs)

fout.close()

subprocess.call(['chmod', '+x', 'down.sh'])


# Dump the mapping from nodes to SSH ports
fout = open('demo.map', 'w')
for vmname in sorted(demo.vms):
    fout.write('%s %d\n' % (vmname, args.base_port + demo.vms[vmname]['id']))
fout.close()


if args.graphviz:
    try:
        import pydot

        colors = ['red', 'green', 'blue', 'orange', 'yellow']
        fcolors = ['black', 'black', 'white', 'black', 'black']

        gvizg = pydot.Dot(graph_type = 'graph')
        i = 0
        for dif in sorted(demo.difs):
            for vmname in demo.dif_graphs[dif]:
                node = pydot.Node(dif + vmname,
                                  label = "%s(%s)" % (vmname, dif),
                                  style = "filled", fillcolor = colors[i],
                                  fontcolor = fcolors[i])
                gvizg.add_node(node)

            for vmname in demo.dif_graphs[dif]:
                for (neigh, lower_dif) in demo.dif_graphs[dif][vmname]:
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
    for dif in demo.dif_ordering:
        if dif in demo.shims or len(demo.difs[dif]) == 0:
            continue

        # Select a pivot node
        pivot = sorted(demo.difs[dif])[0]
        outs += 'echo "Use %(pivot)s as a pivot for DIF %(dif)s"\n'\
                    % {'pivot': pivot, 'dif': dif}
        outs, token = access_prologue(args, demo.vms[pivot], outs)

        for vmname in sorted(demo.difs[dif]):
            outs += '#set -x\n'\
                    'echo "%(pivot)s --> %(vmname)s"\n'\
                    'rina-echo-async -z rina-echo-async.%(vmname)s -d %(dif)s.DIF\n' \
                    '[ "$?" == "0" ] || echo "Failed to reach %(vmname)s ' \
                        'in DIF %(dif)s"\n'\
                        % {'vmname': vmname, 'dif': dif, 'pivot': pivot}

        outs = access_epilogue(args, demo.vms[pivot], outs, token)

    fout.write(outs)
    fout.close()
    subprocess.call(['chmod', '+x', 'echo.sh'])


###### Generate grep script for uipcps log inspection ######
fout = open('greplog.sh', 'w')

outs =  '#!/bin/bash\n'             \
        '\n'                        \
        'if [ -z "$1" ]; then\n'\
        '   echo "Regular expression missing"\n'\
        '   exit 255\n'\
        'fi\n'\

if args.namespaces:
    outs += 'grep "$1" uipcp.*.log\n'
else:
    for vmname in sorted(demo.vms):
        vm = demo.vms[vmname]
        outs += 'echo "Accessing log for node %(vmname)s"\n' % {'vmname': vmname}
        outs, token = access_prologue(args, vm, outs, escape=False)
        outs += 'grep "$1" uipcp.*.log\n'
        outs = access_epilogue(args, vm, outs, token)

fout.write(outs)
fout.close()
subprocess.call(['chmod', '+x', 'greplog.sh'])

###### Generate grep script for kernel log inspection ######
fout = open('grepklog.sh', 'w')

outs =  '#!/bin/bash\n'             \
        '\n'                        \
        'if [ -z "$1" ]; then\n'\
        '   echo "Regular expression missing"\n'\
        '   exit 255\n'\
        'fi\n'\

if args.namespaces:
    outs += 'dmesg | grep "$1"\n'
else:
    for vmname in sorted(demo.vms):
        vm = demo.vms[vmname]
        outs += 'echo "Accessing log for node %(vmname)s"\n' % {'vmname': vmname}
        outs, token = access_prologue(args, vm, outs, escape=False)
        outs += 'dmesg | grep "$1"\n'
        outs = access_epilogue(args, vm, outs, token)

fout.write(outs)
fout.close()
subprocess.call(['chmod', '+x', 'grepklog.sh'])
