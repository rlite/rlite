import subprocess

def gen_program_script(image, base_port, interactive = True):
    fout = open('program.sh', 'w')

    outs =  '#!/bin/bash\n'                                             \
            '\n'                                                        \
            'set -x\n'                                                  \
            'qemu-system-x86_64 "%(img)s" '                             \
            '--enable-kvm '                                             \
            '-smp 2 '                                                   \
            '-m 1G '                                                    \
            '-device e1000,mac=00:0a:0a:0a:0a:99,netdev=mgmt '          \
            '-netdev user,id=mgmt,hostfwd=tcp::%(fwdp)s-:22 '           \
            '-serial tcp:127.0.0.1:%(fwdc)s,server,nowait '             \
            '-vga std ' % {'img': image, 'fwdp': base_port,
                           'fwdc': 10000 + base_port}

    if not interactive:
        outs += '-display none '         \
                '-pidfile program.pid '

    outs += '&\n'

    fout.write(outs)
    fout.close()
    subprocess.call(['chmod', '+x', 'program.sh'])

