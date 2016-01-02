#!/usr/bin/env python

import re
import argparse
import subprocess
import common
import time


description = "Continuous integration for rlite"
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
                       help = "Configuration file for the testsuites",
                       type = str, default = 'testsuite.conf')

args = argparser.parse_args()


subprocess.call(['rm', 'program.pid'])

# Generate program script in non-interactive mode
common.gen_program_script(args.image, args.base_port, False)
subprocess.check_call(['./program.sh'])


# Generate update script
fout = open('ci-update.sh', 'w')

outs =  '#!/bin/bash\n'                                             \
        '\n'                                                        \
        'set -x\n'                                                  \
        ''                                                          \
        'DONE=255\n'\
        'while [ $DONE != "0" ]; do\n'\
        '   ssh -T -p %(ssh)s localhost << \'ENDSSH\'\n' % {'ssh': args.base_port}

outs += '\n'                                                        \
        'cd ~/git/rlite\n'                                          \
        'git fetch %(remote)s\n'                                    \
        'git clean -fdx\n'                                          \
        'git reset HEAD\n'                                          \
        'git checkout .\n'                                          \
        'git checkout %(branch)s\n'                               \
        'git diff origin/%(branch)s > diff.patch\n'                 \
        'if [ -s diff.patch ]; then\n'                              \
        '    echo BRANCHCHANGED\n'                                  \
        '    git merge %(remote)s/%(branch)s\n'                     \
        '    ./configure && make && sudo make install\n'            \
        'else\n'                                                    \
        '    echo BRANCHUNCHANGED\n'                                \
        'fi\n'  % {'branch': 'master', 'remote': 'origin'}

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
subprocess.call(['chmod', '+x', 'ci-update.sh'])

branch_changed = False
try:
    p = subprocess.run(['./ci-update.sh'], stdout = subprocess.PIPE,
                       timeout = 200)
    branch_changed = b'BRANCHCHANGED' in p.stdout
except subprocess.TimeoutExpired:
    print("[ERROR] update script timed out")

print("Branch changed %s" % branch_changed)

# Terminate the program script
try:
    while 1:
        try:
            fin = open('program.pid')
            pid = fin.read().strip()
            fin.close()
            break
        except:
            time.sleep(0.5)
            pass
    subprocess.check_call(['kill', pid])
except:
    print("Cannot kill program script")
    raise
