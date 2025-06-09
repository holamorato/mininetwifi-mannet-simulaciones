#!/usr/bin/python

from mininet.log import setLogLevel, info
from mn_wifi.link import wmediumd, adhoc
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.replaying import ReplayingMobility
from mn_wifi.wmediumdConnector import interference
import random
import sys
import os
import warnings

def topology(args):
    # Ajustes Iniciales
    warnings.filterwarnings("ignore")
    kwargs = {}
    protocols = ['batmand', 'batman_adv']
    for proto in args:
        if proto in protocols:
            kwargs['proto'] = proto
    if 'proto' not in kwargs:
        info("*ERROR: No ha elegido un protocolo entre: batmand o batman_adv\n")
        exit()

    # Generación Semilla Aleatoria
    seed = 2016
    random.seed(seed)

    # Creación de las características de la red
    info("*** CREACION DE LA RED\n")
    info(kwargs)
    info("\n")
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)
    


    # Configuración de la topología de red

    info("*** CONFIGURACION DE TOPOLOGIA\n")
    info("*** Añadiendo nodos a la red\n")
    sta1 = net.addStation('sta1', mac='02:00:00:00:00:01', ip='10.0.0.1', position='0,125,0',   ipv6='fe80::1',  privateDirs=['/var/run','/var/log'], **kwargs)
    sta2 = net.addStation('sta2', mac='02:00:00:00:00:02', ip='10.0.0.2', position='250,100,0', ipv6='fe80::2',  privateDirs=['/var/run','/var/log'], **kwargs)
    sta3 = net.addStation('sta3', mac='02:00:00:00:00:03', ip='10.0.0.3', position='250,150,0', ipv6='fe80::3', privateDirs=['/var/run','/var/log'], **kwargs)
    sta4 = net.addStation('sta4', mac='02:00:00:00:00:04', ip='10.0.0.4', position='250,200,0', ipv6='fe80::4', privateDirs=['/var/run','/var/log'], **kwargs)
    sta5 = net.addStation('sta5', mac='02:00:00:00:00:05', ip='10.0.0.5', position='300,100,0', ipv6='fe80::5', privateDirs=['/var/run','/var/log'], **kwargs)
    sta6 = net.addStation('sta6', mac='02:00:00:00:00:06', ip='10.0.0.6', position='300,150,0', ipv6='fe80::6', privateDirs=['/var/run','/var/log'], **kwargs)
    sta7 = net.addStation('sta7', mac='02:00:00:00:00:07', ip='10.0.0.7', position='300,200,0', ipv6='fe80::7', privateDirs=['/var/run','/var/log'], **kwargs)
    sta8 = net.addStation('sta8', mac='02:00:00:00:00:08', ip='10.0.0.8', position='350,100,0', ipv6='fe80::8', privateDirs=['/var/run','/var/log'], **kwargs)
    sta9 = net.addStation('sta9', mac='02:00:00:00:00:09', ip='10.0.0.9', position='350,150,0', ipv6='fe80::9', privateDirs=['/var/run','/var/log'], **kwargs)
    sta10 = net.addStation('sta10', mac='02:00:00:00:00:0A', ip='10.0.0.10', position='350,200,0', ipv6='fe80::10', privateDirs=['/var/run','/var/log'], **kwargs)
    sta11 = net.addStation('sta11', mac='02:00:00:00:00:0B', ip='10.0.0.11', position='400,150,0', ipv6='fe80::11', privateDirs=['/var/run','/var/log'], **kwargs)
    sta12 = net.addStation('sta12', mac='02:00:00:00:00:0C', ip='10.0.0.12', position='450,150,0', ipv6='fe80::12', privateDirs=['/var/run','/var/log'], **kwargs)
    sta13 = net.addStation('sta13', mac='02:00:00:00:00:0D', ip='10.0.0.13', position='500,150,0', ipv6='fe80::13', privateDirs=['/var/run','/var/log'], **kwargs)
    sta14 = net.addStation('sta14', mac='02:00:00:00:00:0E', ip='10.0.0.14', position='550,100,0', ipv6='fe80::14', privateDirs=['/var/run','/var/log'], **kwargs)
    sta15 = net.addStation('sta15', mac='02:00:00:00:00:0F', ip='10.0.0.15', position='550,150,0', ipv6='fe80::15', privateDirs=['/var/run','/var/log'], **kwargs)
    sta16 = net.addStation('sta16', mac='02:00:00:00:00:10', ip='10.0.0.16', position='550,200,0', ipv6='fe80::16', privateDirs=['/var/run','/var/log'], **kwargs)
    sta17 = net.addStation('sta17', mac='02:00:00:00:00:11', ip='10.0.0.17', position='600,100,0', ipv6='fe80::17', privateDirs=['/var/run','/var/log'], **kwargs)
    sta18 = net.addStation('sta18', mac='02:00:00:00:00:12', ip='10.0.0.18', position='600,150,0', ipv6='fe80::18', privateDirs=['/var/run','/var/log'], **kwargs)
    sta19 = net.addStation('sta19', mac='02:00:00:00:00:13', ip='10.0.0.19', position='600,200,0', ipv6='fe80::19', privateDirs=['/var/run','/var/log'], **kwargs)
    sta20 = net.addStation('sta20', mac='02:00:00:00:00:14', ip='10.0.0.20', position='650,100,0', ipv6='fe80::20', privateDirs=['/var/run','/var/log'], **kwargs)
    sta21 = net.addStation('sta21', mac='02:00:00:00:00:15', ip='10.0.0.21', position='650,150,0', ipv6='fe80::21', privateDirs=['/var/run','/var/log'], **kwargs)
    sta22 = net.addStation('sta22', mac='02:00:00:00:00:16', ip='10.0.0.22', position='650,200,0', ipv6='fe80::22', privateDirs=['/var/run','/var/log'], **kwargs)

    info("*** Configurando modelo de propagación\n")
    net.setPropagationModel(model="logDistance", exp=4)

    info("*** Configurando nodos Wifi\n")
    net.configureWifiNodes()

    info("*** Añadiendo enlaces inalámbricos\n")
    net.addLink(sta1, cls=adhoc, intf='sta1-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta2, cls=adhoc, intf='sta2-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta3, cls=adhoc, intf='sta3-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta4, cls=adhoc, intf='sta4-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta5, cls=adhoc, intf='sta5-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta6, cls=adhoc, intf='sta6-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta7, cls=adhoc, intf='sta7-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta8, cls=adhoc, intf='sta8-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta9, cls=adhoc, intf='sta9-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta10, cls=adhoc, intf='sta10-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta11, cls=adhoc, intf='sta11-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta12, cls=adhoc, intf='sta12-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta13, cls=adhoc, intf='sta13-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta14, cls=adhoc, intf='sta14-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta15, cls=adhoc, intf='sta15-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta16, cls=adhoc, intf='sta16-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta17, cls=adhoc, intf='sta17-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta18, cls=adhoc, intf='sta18-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta19, cls=adhoc, intf='sta19-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta20, cls=adhoc, intf='sta20-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta21, cls=adhoc, intf='sta21-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)
    net.addLink(sta22, cls=adhoc, intf='sta22-wlan0', ssid='skyNet', mode='g', channel=5, **kwargs)

    info("*** CONFIGURANDO MOVILIDAD\n")
    net.isReplaying = True
    path = os.path.dirname(os.path.abspath(__file__)) + '/replayingMobility/trayectoria/'
    generar_movilidad(sta1, '{}movilidad_sta1.dat'.format(path))


    info("*** INICIANDO INTERFAZ GRÁFICA\n")
    net.plotGraph(max_x=800, max_y=350)


    info("*** CONSTRUYENDO RED\n")
    net.build()

    info("\n*** INICIANDO MOVILIDAD\n")
    ReplayingMobility(net)

    info("*** INICIANDO CONSOLA DE COMANDOS\n")
    CLI(net)


    info("*** PARANDO RED\n")
    net.stop()


def generar_movilidad(sta, file_):
    sta.p = []
    sta.time = []
    wait_time = 100

    # Posición inicial (390, 240, 0) 
    pos = (390, 240, 0)
    tim = wait_time
    sta.position = pos
    sta.p.append(pos)
    sta.time.append(tim)

    # Parada entre sta2 y sta3
    pos = (250, 125, 0)
    tim += wait_time
    sta.p.append(pos)
    sta.time.append(tim)

    # Parada entre sta21 y sta22
    pos = (650, 175, 0)
    tim += wait_time
    sta.p.append(pos)
    sta.time.append(tim)

    # Volver indefinidamente a la posición inicial
    pos = (390, 240, 0)
    tim += wait_time
    sta.p.append(pos)
    sta.time.append(tim)
    sta.p.append(pos)  # Mantener indefinidamente
    sta.time.append(float('inf'))
    


if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)