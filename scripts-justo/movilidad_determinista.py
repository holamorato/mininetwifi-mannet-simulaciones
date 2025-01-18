A.1.
Escenarios de movilidad determinista
Código fuente de los escenarios que usan movilidad determinista mediante marcas tempo-
rales.
1from mininet.log import setLogLevel, info
2from mn_wifi.link import wmediumd, adhoc
3from mn_wifi.cli import CLI
4from mn_wifi.net import Mininet_wifi
5from mn_wifi.replaying import ReplayingMobility
6from mn_wifi.wmediumdConnector import interference
7import sys
8import os
9import warnings
10
11
12
def topology(args):
13warnings.filterwarnings("ignore")
14net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)
15info("*** Creating nodes\n")
16kwargs = {}
17sta1 = net.addStation('sta1', ip='10.10.0.1/24',
,→
18
position='25,250,0', mac='02:00:00:00:65:01', **kwargs)
sta2 = net.addStation('sta2', ip='10.10.0.2/24',
,→
position='75,250,0', mac='02:00:00:00:65:02', **kwargs)
5758
19
APÉNDICE A. ESCENARIOS DE MOVILIDAD EN MININET WIFI
sta3 = net.addStation('sta3', ip='10.10.0.3/24',
,→
20
sta4 = net.addStation('sta4', ip='10.10.0.4/24',
,→
21
position='375,250,0', mac='02:00:00:00:65:08', **kwargs)
sta9 = net.addStation('sta9', ip='10.10.0.9/24', position='425,
,→
26
position='325,250,0', mac='02:00:00:00:65:07', **kwargs)
sta8 = net.addStation('sta8', ip='10.10.0.8/24',
,→
25
position='275,250,0', mac='02:00:00:00:65:06', **kwargs)
sta7 = net.addStation('sta7', ip='10.10.0.7/24',
,→
24
position='225,250,0', mac='02:00:00:00:65:05', **kwargs)
sta6 = net.addStation('sta6', ip='10.10.0.6/24',
,→
23
position='175,250,0', mac='02:00:00:00:65:04', **kwargs)
sta5 = net.addStation('sta5', ip='10.10.0.5/24',
,→
22
position='125,250,0', mac='02:00:00:00:65:03', **kwargs)
250, 0', mac='02:00:00:00:65:09', **kwargs)
sta10 = net.addStation('sta10', ip='10.10.0.10/24',
,→
mac='02:00:00:00:65:10', **kwargs)
27
28
net.setPropagationModel(model="logDistance", exp=4)
29
30info("*** Configuring wifi nodes\n")
31net.configureWifiNodes()
32
33info("*** Creating links\n")
34protocols = ['batman_adv', 'olsrd', 'olsrd2']
35for proto in args:
if proto in protocols:
36
kwargs['proto'] = proto
37
if 'proto' not in kwargs:
38
info("*INFO: No protocol selected*\n")
39
40
41
net.addLink(sta1, cls=adhoc, intf='sta1-wlan0', ssid='adhocNet',
,→
42
net.addLink(sta2, cls=adhoc, intf='sta2-wlan0', ssid='adhocNet',
,→
43
mode='g', channel=5, **kwargs)
mode='g', channel=5, **kwargs)
net.addLink(sta3, cls=adhoc, intf='sta3-wlan0', ssid='adhocNet',
,→
mode='g', channel=5, **kwargs)A.1. ESCENARIOS DE MOVILIDAD DETERMINISTA
44
net.addLink(sta4, cls=adhoc, intf='sta4-wlan0', ssid='adhocNet',
,→
45
mode='g', channel=5, **kwargs)
net.addLink(sta9, cls=adhoc, intf='sta9-wlan0', ssid='adhocNet',
,→
50
mode='g', channel=5, **kwargs)
net.addLink(sta8, cls=adhoc, intf='sta8-wlan0', ssid='adhocNet',
,→
49
mode='g', channel=5, **kwargs)
net.addLink(sta7, cls=adhoc, intf='sta7-wlan0', ssid='adhocNet',
,→
48
mode='g', channel=5, **kwargs)
net.addLink(sta6, cls=adhoc, intf='sta6-wlan0', ssid='adhocNet',
,→
47
mode='g', channel=5, **kwargs)
net.addLink(sta5, cls=adhoc, intf='sta5-wlan0', ssid='adhocNet',
,→
46
mode='g', channel=5, **kwargs)
net.addLink(sta10, cls=adhoc, intf='sta10-wlan0', ssid='adhocNet',
,→
mode='g', channel=5, **kwargs)
51
52net.isReplaying = True
53path = os.path.dirname(os.path.abspath(__file__)) +
,→
54
'/replayingMobility/escenario2/'
get_trace(sta10, '{}node.dat'.format(path), 10)
55
56
if '-p' in args:
net.plotGraph(max_x=500, max_y=500)
57
58
59info("*** Starting network\n")
60net.build()
61
62info("\n*** Replaying Mobility\n")
63ReplayingMobility(net)
64
65info("*** Running CLI\n")
66CLI(net)
67
68info("*** Stopping network\n")
69net.stop()
70
71
72
59
def get_trace(sta, file_, numeral):60
APÉNDICE A. ESCENARIOS DE MOVILIDAD EN MININET WIFI
73file_ = open(file_, 'r')
74raw_data = file_.readlines()
75file_.close()
76sta.p = []
77sta.time = []
78if numeral == 10:
79pos = (25, 200, 0)
80tim = 30
elif numeral == 1:
81
82pos = (25, 250, 0)
83tim = 30
else:
84
85pos = (0, 0, 0)
86tim = 30
87sta.position = pos
88sta.time.append(tim)
89for data in raw_data:
90line = data.split()
91x = line[0]
# First Column
92y = line[1]
# Second Column
93t = line[2]
# Third column
94pos = float(x), float(y), 0.0
95tim = float(t)
96sta.p.append(pos)
97sta.time.append(tim)
98
99
100
if __name__ == '__main__':
101setLogLevel('info')
102topology(sys.argv)