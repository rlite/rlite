#!/usr/bin/env python
#
# Extracts enrollment events from the logs on all the nodes and sorts them by
# time of enrollment.
#

import subprocess
import re
import os


class EnrollEvent:
    def __init__(self, node, hr, mi, sec):
        self.node = node
        self.hr = hr
        self.mi = mi
        self.sec = sec

    def __repr__(self):
        return "%s at %02d:%02d:%02d" % (self.node, self.hr, self.mi, self.sec)


o = subprocess.check_output(['./greplog.sh', 'Enroller enabled'])
o = str(o)
if o.startswith("b'"):
    o = o[2:]
o = o.split('\\n')

events = []
i = 0
while i < len(o) - 1:
    m1 = re.search(r'log for node (\S+)', o[i])
    m2 = re.search(r'(\d\d):(\d\d):(\d\d)', o[i+1])
    if m1 is not None and m2 is not None:
        node = m1.group(1)
        hr, mi, sec = int(m2.group(1)), int(m2.group(2)), int(m2.group(3))
        t = hr * 3600 + mi * 60 + sec
        events.append(EnrollEvent(node, hr, mi, sec))
        i += 2
    else:
        i += 1

events.sort(key = lambda x: (3600*x.hr+60*x.mi+x.sec))

for e in events:
    print(e)
