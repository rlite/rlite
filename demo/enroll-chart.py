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

    def timestamp(self):
        return 3600*self.hr+60*self.mi+self.sec


o = subprocess.check_output(['./greplog.sh', 'Enroller enabled'])
o = str(o)
if o.startswith("b'"):
    o = o[2:]
o = o.replace('\\n', '\n')
o = o.split('\n')

events = []
for line in o:
    m1 = re.search(r'uipcp\.([^.]+)\.log', line)
    m2 = re.search(r'(\d\d):(\d\d):(\d\d)', line)
    if m1 is not None and m2 is not None:
        node = m1.group(1)
        hr, mi, sec = int(m2.group(1)), int(m2.group(2)), int(m2.group(3))
        t = hr * 3600 + mi * 60 + sec
        events.append(EnrollEvent(node, hr, mi, sec))

# Sort by time
events.sort(key = lambda x: (x.timestamp()))

if len(events) == 0:
    # Nothing to do
    quit(0)

# Print the sorted events
for e in events:
    print(e)

first_t = events[0].timestamp()

# Group by time, computing a cumulative count
cumcounts = dict()
last_time = -1
count_partial = 0
count_total = 0
for i in range(len(events)):
    count_partial += 1
    t = events[i].timestamp()
    if i+1 < len(events):
        t_next = events[i+1].timestamp()
    else:
        t_next = -2  # invalid
    if t_next != t:
        # Finalize the last group
        count_total += count_partial
        cumcounts[t-first_t] = count_total
        # Start a new group
        count_partial = 0

for t in sorted(cumcounts):
    print("t=%04d: %4d enrolled" % (t, cumcounts[t]))
    #print("%4d %4d" % (t, cumcounts[t]))
