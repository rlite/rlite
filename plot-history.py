#!/usr/bin/env python

# Requires the following packages
#  math/py-matplotlib
#  math/py-numpy

import matplotlib.pyplot as plt
import numpy as np
import sys
import re


# Input arguments
if len(sys.argv) < 2:
    print("USAGE: cmd INPUTFILE")
    quit()

try:
    fin = open(sys.argv[1], "r")
except IOError:
    print(sys.argv[1], ": no such file")
    quit()

# set default values
title = 'History'
ylabel = 'lines of code'
xlabel = 'time'
legend = 'upper left'
#linestyles = ['x', '--', ':', 'o', 'v', 's', '+', '1', '2', '3', '4' ]
linestyles = ['x-', '^-', 'o-', 's-', 'v-', '2-', '3-', '4-']
#for more linestyles see "http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.plot"

x = []
y = []
while 1:
    line = fin.readline()
    if line == '':
        break
    line = line.replace('\n', '').replace('\t', ' ')
    spl = line.split(' ')
    if len(spl) != 2:
        continue
    x.append(spl[0])
    y.append(spl[1])


# Graphics
plt.title(title)
if xlabel:
    plt.xlabel(xlabel, fontsize=18)
plt.ylabel(ylabel, fontsize=18)
#plt.ylim([0, best_result * 1.1])
leg = []
lab = []
for j in range(len(x)):
    x[j] = float(x[j])

xspan = x[-1] - x[0]
LEFT_OFFSET = 0.05*xspan
plt.xlim([x[0]-LEFT_OFFSET, x[-1]+LEFT_OFFSET])

# make plots in blue or black ?
pl = plt.plot(x, y, '.-', linewidth=2,
                markersize = 2, antialiased=True)
leg.append(pl[0])
lab.append('lines of code')

plt.legend(leg, lab, loc=legend, prop={'size': 16})
plt.show()  #debug
#outfn = sys.argv[1].rsplit('.',1)[0]
#plt.savefig(outfn + '.eps')

