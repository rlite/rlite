#!/usr/bin/env python

import re
import argparse
import subprocess
import common


description = "Python script to launch a scenario"
epilog = "2015 Vincenzo Maffione <v.maffione@gmail.com>"

argparser = argparse.ArgumentParser(description = description,
                                    epilog = epilog)
argparser.add_argument('-p', '--base-port',
                       help = "Base port for VMs",
                       type = int, default = 2222)
argparser.add_argument('-i', '--image',
                       help = "Path to the VM image", type = str,
                       default = '/home/vmaffione/git/vm/arch.qcow2')
argparser.add_argument('-l', '--levels',
                       help = "Number of stacked normal DIFs [>0]",
                       type = int, default = 1)
argparser.add_argument('-t', '--type',
                       help = "",
                       choices = ['eth', 'inet4', 'null'], default = 'eth')
argparser.add_argument('-c', '--conf',
                       help = "Path to the topology configuration file", type = str,
                       default = 'gen.conf')
argparser.add_argument('--no-program-script', dest='program_script',
                       action='store_false', help = "Don't generate program script")
argparser.add_argument('-m', '--vm-memory',
                       help = "Memory of each VM, in MiB",
                       type = int, default = 256)
argparser.add_argument('--quiet', dest='quiet',
                       action='store_true', help = "Don't use set -x in bash scripts")

args = argparser.parse_args()


if args.levels < 1:
    args.levels = 1
    print("Warning: levels set to %d" % (args.levels))

if args.vm_memory < 32:
    args.vm_memory = 32
    print("Warning: vm_memory set to %d" % (args.vm_memory))

try:
    fin = open(args.conf, 'r')
except:
    print("Could not open topology configuration file %s" % args.conf)
    quit(1)

vms = dict()
bridges = dict()
links = []

while 1:
    line = fin.readline()
    if line == '':
        break

    line = line.replace('\n', '')

    if line.startswith('#'):
        continue

    m = re.match(r'\s*vm\s+(\w+)', line)
    if m:
        name = m.group(1)
        vms[name] = {'name': name, 'ports': []}
        continue

    m = re.match(r'\s*bridge\s+(\w+)', line)
    if m:
        name = m.group(1)
        bridges[name] = {'name': name, 'vms': []}
        continue

    m = re.match(r'\s*link\s+(\w+)\s+(\w+)', line)
    if m:
        bridge = m.group(1)
        vm = m.group(2)
        links.append((bridge, vm))
        continue

fin.close()

print(vms)
print(bridges)
print(links)


################### GENERATE UP SCRIPT #####################

fout = open('up.sh', 'w')

outs =  '#!/bin/bash\n'             \
        '\n'
if not args.quiet:
    outs += 'set -x\n'                  \
            '\n';

brid = 1

for b in sorted(bridges):
    outs += 'sudo brctl addbr %(br)s\n'         \
            'sudo ip link set %(br)s up\n'      \
            '\n' % {'br': b}

    bridges[b]['id'] = brid

    brid += 1

for l in links:
    b, vm = l
    idx = len(vms[vm]['ports']) + 1
    tap = '%s.%02x' % (vm, idx)

    outs += 'sudo ip tuntap add mode tap name %(tap)s\n'    \
            'sudo ip link set %(tap)s up\n'                 \
            'sudo brctl addif %(br)s %(tap)s\n\n'           \
                % {'tap': tap, 'br': b}

    vms[vm]['ports'].append({'tap': tap, 'br': b, 'idx': idx})
    bridges[b]['vms'].append(vm)


vmid = 1

for i in sorted(vms):
    vm = vms[i]

    vm['id'] = vmid

    fwdp = args.base_port + vmid
    mac = '00:0a:0a:0a:%02x:%02x' % (vmid, 99)

    vm['ssh'] = fwdp

    outs += ''                                                          \
            'qemu-system-x86_64 "%(img)s" '                             \
            '-snapshot '                                                \
            '--enable-kvm '                                             \
            '-smp 2 '                                                   \
            '-m %(memory)sM '                                                  \
            '-device e1000,mac=%(mac)s,netdev=mgmt '                    \
            '-netdev user,id=mgmt,hostfwd=tcp::%(fwdp)s-:22 '           \
            '-vga std '                                                 \
            '-pidfile rina-%(id)s.pid '                                 \
            '-display none '                                            \
            '-serial tcp:127.0.0.1:%(fwdc)s,server,nowait '\
             % {'fwdp': fwdp, 'id': vmid, 'mac': mac, 'fwdc': fwdp + 10000,
                'img': args.image, 'memory': args.vm_memory}

    for port in vm['ports']:
        tap = port['tap']
        mac = '00:0a:0a:0a:%02x:%02x' % (vmid, port['idx'])
        port['mac'] = mac

        outs += ''                                                      \
        '-device virtio-net-pci,mac=%(mac)s,netdev=data%(idx)s '        \
        '-netdev tap,ifname=%(tap)s,id=data%(idx)s,script=no,downscript=no '\
            % {'mac': mac, 'tap': tap, 'idx': port['idx']}

    outs += '&\n\n'

    vmid += 1

inet4_dir = []

for i in sorted(vms):
    vm = vms[i]

    d = {'name': vm['name'], 'ssh': vm['ssh'],
                   'id': vm['id'], 'levels': args.levels,
                   'shimtype': args.type}

    outs += ''\
            'DONE=255\n'\
            'while [ $DONE != "0" ]; do\n'\
            '   ssh -T -p %(ssh)s localhost << \'ENDSSH\'\n' % d
    if not args.quiet:
        outs += 'set -x\n'
    outs += 'sudo hostname %(name)s\n'\
            '\n'\
            '[ "%(shimtype)s" == "null" ] && cd /usr/bin/ && sudo ln -sf true rlite-ctl\n'\
            '\n'\
            'sudo modprobe rlite\n'\
            'sudo modprobe rlite-shim-%(shimtype)s\n'\
            'sudo modprobe rlite-normal\n'\
            'sudo chmod a+rwx /dev/rlite\n'\
            'sudo chmod a+rwx /dev/rlite-io\n'\
            'sudo mkdir -p /var/rlite\n'\
            'sudo chmod -R a+rw /var/rlite\n'\
            '\n'\
            'sudo rlite-uipcps &> uipcp.log &\n'\
            '\n'\
            'for i in $(seq 1 %(levels)s); do\n'\
            '   rlite-ctl ipcp-create n.${i}.IPCP %(id)s normal n.${i}.DIF\n'\
            '   rlite-ctl ipcp-config n.${i}.IPCP %(id)s address %(id)d\n'\
            'done\n'\
            '\n' % d

    for port in vm['ports']:
        vars_dict = {'mac': port['mac'], 'idx': port['idx'],
                     'id': vm['id'], 'brid': bridges[port['br']]['id'],
                     'shimtype': args.type}
        outs += 'PORT=$(mac2ifname %(mac)s)\n'\
                'sudo ip link set $PORT up\n'\
                'rlite-ctl ipcp-create e.%(brid)s.IPCP %(idx)s shim-%(shimtype)s e.%(brid)s.DIF\n' % vars_dict
        if args.type == 'eth':
                outs += 'rlite-ctl ipcp-config e.%(brid)s.IPCP %(idx)s netdev $PORT\n' % vars_dict
        elif args.type == 'inet4':
                outs += 'sudo ip addr add 10.71.%(brid)s.%(id)s/24 dev $PORT\n' % vars_dict
                entry = 'n.1.IPCP/%(id)s// 10.71.%(brid)s.%(id)s 9876 e.%(brid)s.DIF' % vars_dict
                outs += 'sudo sh -c \'echo "%s" >> /etc/rlite/shim-inet4-dir\'\n' % (entry, )
                inet4_dir.append(entry)
        outs += 'rlite-ctl ipcp-register e.%(brid)s.DIF n.1.IPCP %(id)s\n'\
                '\n' % vars_dict

    outs += 'for i in $(seq 2 %(levels)s); do\n'\
            '   rlite-ctl ipcp-register n.$(($i-1)).DIF n.$i.IPCP %(id)s\n'\
            'done\n'\
            'true\n'\
            'ENDSSH\n'\
            '   DONE=$?\n'\
            '   if [ $DONE != "0" ]; then\n'\
            '       sleep 1\n'\
            '   fi\n'\
            'done\n\n' % {'id': vm['id'], 'levels': args.levels}

if args.type == 'inet4':
    print(inet4_dir)

    for i in vms:
        vm = vms[i]

        outs += ''\
                'DONE=255\n'\
                'while [ $DONE != "0" ]; do\n'\
                '   ssh -T -p %(ssh)s localhost << \'ENDSSH\'\n' % {'ssh': vm['ssh']}

        for entry in inet4_dir:
                outs += 'sudo sh -c \'echo "%s" >> /etc/rlite/shim-inet4-dir\'\n' % (entry, )

        outs += 'true\n'\
                'ENDSSH\n'\
                '   DONE=$?\n'\
                '   if [ $DONE != "0" ]; then\n'\
                '       sleep 1\n'\
                '   fi\n'\
                'done\n\n'

for br_name in sorted(bridges):
    b = bridges[br_name]

    if len(b['vms']) == 1:
        # No enrollment needed
        continue

    # Select the pivot VM ad libitum
    for vm_name in b['vms']:
        pvm = vms[vm_name]
        break

    for vm_name in b['vms']:
        if vm_name == pvm['name']:
            continue

        vm = vms[vm_name]

        d = {'ssh': vm['ssh'], 'id': vm['id'],
             'pvid': pvm['id'], 'brid': b['id']}

        # Enroll against the pivot

        outs += ''\
                'DONE=255\n'\
                'while [ $DONE != "0" ]; do\n'\
                '   ssh -T -p %(ssh)s localhost << \'ENDSSH\'\n' % d
        if not args.quiet:
            outs += 'set -x\n'
        outs += 'rlite-ctl ipcp-enroll n.1.DIF n.1.IPCP %(id)s '\
                                    'n.1.IPCP %(pvid)s e.%(brid)s.DIF\n'\
                'true\n'\
                'ENDSSH\n'\
                '   DONE=$?\n'\
                '   if [ $DONE != "0" ]; then\n'\
                '       sleep 1\n'\
                '   fi\n'\
                'done\n\n' % d


# Select the pivot VM ad libitum
for i in sorted(vms):
    pvm = vms[i]

for level in range(2, args.levels + 1):
    for vm_name in sorted(vms):
        if vm_name == pvm['name']:
            continue

        vm = vms[vm_name]

        d = {'ssh': vm['ssh'], 'id': vm['id'],
             'pvid': pvm['id'], 'level': level,
              'lm1': level - 1}

        # Enroll against the pivot

        outs += ''\
                'DONE=255\n'\
                'while [ $DONE != "0" ]; do\n'\
                '   ssh -T -p %(ssh)s localhost << \'ENDSSH\'\n' % d
        if not args.quiet:
            outs += 'set -x\n'
        outs += 'rlite-ctl ipcp-enroll n.%(level)s.DIF n.%(level)s.IPCP %(id)s '\
                            'n.%(level)s.IPCP %(pvid)s n.%(lm1)s.DIF\n'\
                'true\n'\
                'ENDSSH\n'\
                '   DONE=$?\n'\
                '   if [ $DONE != "0" ]; then\n'\
                '       sleep 1\n'\
                '   fi\n'\
                'done\n\n' % d

fout.write(outs)
fout.close()
subprocess.call(['chmod', '+x', 'up.sh'])

print(vms)


################### GENERATE DOWN SCRIPT #####################

fout = open('down.sh', 'w')

outs =  '#!/bin/bash\n'             \
        '\n'
if not args.quiet:
    outs += 'set -x\n'
outs += '\n'                        \
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

for i in sorted(vms):
    vm = vms[i]
    outs += 'kill_qemu rina-%(id)s.pid\n' % {'id': vm['id']}

outs += '\n'

for i in sorted(vms):
    vm = vms[i]
    for port in vm['ports']:
        tap = port['tap']
        b = port['br']

        outs += 'sudo brctl delif %(br)s %(tap)s\n'             \
                'sudo ip link set %(tap)s down\n'               \
                'sudo ip tuntap del mode tap name %(tap)s\n\n'  \
                    % {'tap': tap, 'br': b}

for b in sorted(bridges):
    outs += 'sudo ip link set %(br)s down\n'        \
            'sudo brctl delbr %(br)s\n'             \
            '\n' % {'br': b}

fout.write(outs)
fout.close()
subprocess.call(['chmod', '+x', 'down.sh'])


################### GENERATE PROGRAM SCRIPT #####################
if args.program_script:
    common.gen_program_script(args.image, args.base_port)


################### GENERATE TEST SCRIPT #####################

fout = open('test-server.sh', 'w')

outs =  '#!/bin/bash\n'                                             \
        '\n'
if not args.quiet:
    outs += 'set -x\n'

# Run rinaperf in server mode on the pivot machine, at all layers
outs += ''\
        'DONE=255\n'\
        'while [ $DONE != "0" ]; do\n'\
        '   ssh -T -p %(ssh)s localhost << \'ENDSSH\'\n' % {'ssh': pvm['ssh']}

for level in range(1, args.levels + 1):
    outs += 'rinaperf -l -d n.%(level)s.DIF &> /dev/null &\n' % {'level' : level}

outs += 'sleep 1\n'\
        'true\n'\
        'ENDSSH\n'\
        '   DONE=$?\n'\
        '   if [ $DONE != "0" ]; then\n'\
        '       sleep 1\n'\
        '   fi\n'\
        'done\n\n'

fout.write(outs)
fout.close()
subprocess.call(['chmod', '+x', 'test-server.sh'])


fout = open('test-client.sh', 'w')

outs =  '#!/bin/bash\n'                                             \
        '\n'
if not args.quiet:
    outs += 'set -x\n'

# Run rinaperf in client mode on all but the pivot machine, at all layers,
# towards the server running on the pivot machine
for vm_name in sorted(vms):
    if vm_name == pvm['name']:
        continue

    vm = vms[vm_name]

    outs += ''\
            'DONE=255\n'\
            'while [ $DONE != "0" ]; do\n'\
            '   ssh -T -p %(ssh)s localhost << \'ENDSSH\'\n' % {'ssh': vm['ssh']}

    if not args.quiet:
        outs += 'set -x\n'

    for level in range(1, args.levels + 1):
        outs += 'rinaperf -c 10 -d n.%(level)s.DIF\n' % {'level': level}

    outs += 'sleep 0.2\n'\
            'true\n'\
            'ENDSSH\n'\
            '   DONE=$?\n'\
            '   if [ $DONE != "0" ]; then\n'\
            '       sleep 1\n'\
            '   fi\n'\
            'done\n\n'

fout.write(outs)
fout.close()
subprocess.call(['chmod', '+x', 'test-client.sh'])
