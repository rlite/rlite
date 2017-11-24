if (!exists("unrelfile")) unrelfile='out1.txt'
if (!exists("relfile")) relfile='out2.txt'
if (!exists("mytitle")) mytitle='Throughput tests'

set title mytitle
set xlabel "Packet size (bytes)"
set ylabel "Throughput (Gbps)"
set grid xtics lw 1 lt 0
set grid ytics lw 1 lt 0
set xtics 0,100,1500
set ytics 0,1,13
set xrange [-10:1500]
set yrange [-0.5:13.5]
set key left top
plot unrelfile using 1:($7/1000) title 'Unreliable sender' with linespoints lw 2 ps 1 pt 6 lt rgb "red", \
     unrelfile using 1:($9/1000) title 'Unreliable receiver' with linespoints lw 2 ps 1 pt 6 lt rgb "#00AA00", \
     relfile using 1:($7/1000) title 'Reliable sender/receiver' with linespoints lw 2 ps 1 pt 6 lt rgb "blue"
pause -1
