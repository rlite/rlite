#!/usr/bin/env python

#
# Author: Vincenzo Maffione <v.maffione@gmail.com>
#

import multiprocessing
import subprocess
import statistics
import argparse
import time
import re
import os


def has_outliers(tuples):
    for t in range(len(tuples[0])):
        avg = statistics.mean([x[t] for x in tuples])
        stdev = statistics.stdev([x[t] for x in tuples])
        if stdev > avg*0.05:
            return True
    return False

def to_avg_stdev(vlist, nsamples):
    # Sort by kpps or ktts
    tuples = sorted(vlist[-nsamples:], key=lambda x: x[1])
    left = 0
    vals = []
    while left < len(tuples):
        if not has_outliers(tuples[left:]):
            for t in range(len(tuples[0])):
                avg = statistics.mean([x[t] for x in tuples[left:]])
                stdev = statistics.stdev([x[t] for x in tuples[left:]])
                vals.append(avg)
                vals.append(stdev)
            break
        left += 1
    del vlist[-nsamples:]
    vlist.append(tuple(vals))


description = "Python script to perform automated tests based on rinaperf"
epilog = "2017 Vincenzo Maffione <v.maffione@gmail.com>"

argparser = argparse.ArgumentParser(description = description,
                                    epilog = epilog)
argparser.add_argument('--size-min', type = int, default = 2,
                       help = "Minimum size for the test")
argparser.add_argument('--size-max', type = int, default = 1400,
                       help = "Maximum size for the test")
argparser.add_argument('--size-step', type = int, default = 10,
                       help = "Packet size increment")
argparser.add_argument('--trials', type = int, default = 3,
                       help = "Number of trials for each combination "
                              "of parameters")
argparser.add_argument('-D', '--duration', type = int, default = 10,
                       help = "Duration of each test (in seconds)")
argparser.add_argument('-g', '--max-sdu-gap', type = int, default = -1,
                       help = "Max SDU gap")
argparser.add_argument('-t', '--test-type', type = str, default = "perf",
                       help = "Test type", choices = ["perf", "rr"])
argparser.add_argument('-d', '--dif', type = str,
                        help = "DIF to use for the tests")
argparser.add_argument('-o', '--output', type = str, help = "Output file for gnuplot data",
                        default = 'output.txt')
argparser.add_argument('--sleep', type = int, default = 2,
                       help = "How many seconds to sleep between two consecutive test runs")
args = argparser.parse_args()


stats = []

plotcols = ['size', 'snd_kpps', 'snd_mbps']
if args.test_type == 'perf':
    plotcols += ['rcv_kpps', 'rcv_mbps']
elif args.test_type == 'rr':
    plotcols += ['snd_latency']

# build QoS
qosarg = ""
if args.max_sdu_gap >= 0:
    qosarg += " -g %s" % args.max_sdu_gap

difarg = ""
if args.dif:
    difarg = " -d %s" % args.dif

try:
    for sz in range(args.size_min, args.size_max+1, args.size_step):
        cmd = ("rinaperf -s %s -t %s -D %s %s %s"
                % (sz, args.test_type, args.duration, qosarg, difarg))
        print("Running: %s" % cmd)
        t = 1
        while t <= args.trials:
            try:
                out = subprocess.check_output(cmd.split())
            except subprocess.CalledProcessError:
                print("Test run #%d failed" % t)
                continue
            out = out.decode('ascii')
            outl = out.split('\n')

            if args.test_type == 'perf':

                if len(outl) < 4:
                    print(out)
                    continue

                m = re.match(r'^Sender\s+(\d+)\s+(\d+\.?\d*)\s+(\d+\.?\d*)', outl[2])
                if m is None:
                    print(out)
                    continue

                tpackets = int(m.group(1))
                tkpps = float(m.group(2))
                tmbps = float(m.group(3))

                m = re.match(r'^Receiver\s+(\d+)\s+(\d+\.?\d*)\s+(\d+\.?\d*)', outl[3])
                if m is None:
                    print(out)
                    continue

                rpackets = int(m.group(1))
                rkpps = float(m.group(2))
                rmbps = float(m.group(3))

                prtuple = (tpackets, rpackets, tkpps, rkpps, tmbps, rmbps)
                stats.append((sz, tkpps, rkpps, tmbps, rmbps))

                print("%d/%d pkts %.3f/%.3f Kpps %.3f/%.3f Mbps" % prtuple)

            elif args.test_type == 'rr':

                if len(outl) < 3:
                    print(out)
                    continue

                m = re.match(r'^Sender\s+(\d+)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+)', outl[2])
                if m is None:
                    print(out)
                    continue

                transactions = int(m.group(1))
                ktps = float(m.group(2))
                mbps = float(m.group(3))
                latency = int(m.group(4))

                prtuple = (transactions, ktps, mbps, latency)
                stats.append((sz, ktps, mbps, latency))

                print("%d transactions %.3f Ktps %.3f Mbps %d ns" % prtuple)

            else:
                assert(False)

            t += 1
            time.sleep(args.sleep)

        # Transform the last args.trials element of the 'stats' vectors into
        # a (avg, stddev) tuple.
        to_avg_stdev(stats, args.trials)

except KeyboardInterrupt:
    pass


# Dump statistics for gnuplot
fout = open(args.output, 'w')
s = '#'
for k in plotcols:
    s += '%19s ' % k
fout.write("%s\n" % s)
for i in range(len(stats)):  # num samples
    s = ' '
    for j in range(len(stats[i])):
        s += '%9.1f ' % stats[i][j]
    fout.write("%s\n" % s)
