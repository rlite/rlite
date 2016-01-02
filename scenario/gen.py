#!/usr/bin/env python

import re
import subprocess


fin = open('gen.conf', 'r')

vms = dict()
bridges = dict()
links = []

while 1:
    line = fin.readline()
    if line == '':
        break

    line = line.replace('\n', '')

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
        '\n'                        \
        'set -x\n'                  \
        '\n';

brid = 1

for b in bridges:
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

for i in vms:
    vm = vms[i]

    vm['id'] = vmid

    fwdp = 2222 + vmid
    mac = '00:0a:0a:0a:%02x:%02x' % (vmid, 99)

    vm['ssh'] = fwdp

    outs += ''                                                  \
            'qemu-system-x86_64 "/home/vmaffione/git/vm/arch.qcow2" '   \
            '-snapshot '                                                \
            '--enable-kvm '                                             \
            '-smp 2 '                                                   \
            '-m 512M '                                                  \
            '-device e1000,mac=%(mac)s,netdev=mgmt '                    \
            '-netdev user,id=mgmt,hostfwd=tcp::%(fwdp)s-:22 '           \
            '-vga std '                                                 \
            '-pidfile rina-%(id)s.pid '                                 \
            '-display none ' % {'fwdp': fwdp, 'id': vmid, 'mac': mac}

    for port in vm['ports']:
        tap = port['tap']
        mac = '00:0a:0a:0a:%02x:%02x' % (vmid, port['idx'])
        port['mac'] = mac

        outs += ''                                                      \
        '-device virtio-net-pci,mac=%(mac)s,netdev=data '               \
        '-netdev tap,ifname=%(tap)s,id=data,script=no,downscript=no '   \
            % {'mac': mac, 'tap': tap}

    outs += '&\n\n'

    vmid += 1

for i in vms:
    vm = vms[i]

    outs += ''\
            'DONE=255\n'\
            'while [ $DONE != "0" ]; do\n'\
            '   ssh -p %(ssh)s localhost << \'ENDSSH\'\n'\
            'sudo hostname %(name)s\n'\
            '\n'\
            'sudo modprobe rinalite\n'\
            'sudo modprobe rinalite-shim-eth\n'\
            'sudo modprobe rinalite-normal\n'\
            'sudo chmod a+rwx /dev/rinalite\n'\
            'sudo chmod a+rwx /dev/rina-io\n'\
            'sudo mkdir -p /var/rinalite\n'\
            'sudo chmod -R a+rw /var/rinalite\n'\
            '\n'\
            'rinalite-uipcps &> uipcp.log &\n'\
            'rina-config ipcp-create n.IPCP %(id)s normal n.DIF\n'\
            'rina-config ipcp-config n.IPCP %(id)s address %(id)d\n'\
            '\n' % {'name': vm['name'], 'ssh': vm['ssh'],
                   'id': vm['id']}

    for port in vm['ports']:
        outs += 'PORT=$(mac2ifname %(mac)s)\n'\
                'sudo ip link set $PORT up\n'\
                'rina-config ipcp-create e.%(brid)s.IPCP %(idx)s shim-eth e.%(brid)s.%(idx)s.DIF\n'\
                'rina-config ipcp-config e.%(brid)s.IPCP %(idx)s netdev $PORT\n'\
                'rina-config ipcp-register e.%(brid)s.%(idx)s.DIF n.IPCP %(id)s\n'\
                'true\n'\
                    % {'mac': port['mac'], 'idx': port['idx'],
                       'id': vm['id'], 'brid': bridges[port['br']]['id']}

    outs += 'ENDSSH\n'\
            '   DONE=$?\n'\
            '   if [ $DONE != "0" ]; then\n'\
            '       sleep 1\n'\
            '   fi\n'\
            'done\n\n'


for br_name in bridges:
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

        port = None

        for p in vm['ports']:
            if p['br'] == b['name']:
                port = p
                break

        assert(port != None)

        # Enroll against the pivot

        outs += ''\
            'DONE=255\n'\
            'while [ $DONE != "0" ]; do\n'\
            '   ssh -p %(ssh)s localhost << \'ENDSSH\'\n'\
            'rina-config ipcp-enroll n.DIF n.IPCP %(id)s '\
                                    'n.IPCP %(pvid)s e.%(brid)s.%(idx)s.DIF\n'\
            'ENDSSH\n'\
            '   DONE=$?\n'\
            '   if [ $DONE != "0" ]; then\n'\
            '       sleep 1\n'\
            '   fi\n'\
            'done\n\n' % {'ssh': vm['ssh'], 'id': vm['id'],
                          'pvid': pvm['id'], 'brid': b['id'],
                          'idx': port['idx']}

fout.write(outs)

fout.close()

subprocess.call(['chmod', '+x', 'up.sh'])

print(vms)


################### GENERATE DOWN SCRIPT #####################

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

for i in vms:
    vm = vms[i]
    outs += 'kill_qemu rina-%(id)s.pid\n' % {'id': vm['id']}

outs += '\n'

for i in vms:
    vm = vms[i]
    for port in vm['ports']:
        tap = port['tap']
        b = port['br']

        outs += 'sudo brctl delif %(br)s %(tap)s\n'             \
                'sudo ip link set %(tap)s down\n'               \
                'sudo ip tuntap del mode tap name %(tap)s\n\n'  \
                    % {'tap': tap, 'br': b}

for b in bridges:
    outs += 'sudo ip link set %(br)s down\n'        \
            'sudo brctl delbr %(br)s\n'             \
            '\n' % {'br': b}

fout.write(outs)

fout.close()

subprocess.call(['chmod', '+x', 'down.sh'])
