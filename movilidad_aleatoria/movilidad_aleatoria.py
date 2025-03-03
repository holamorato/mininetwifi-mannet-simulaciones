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
    sta1 = net.addStation('sta1', mac='02:00:00:00:00:01', ip='10.0.0.1', position='0,125,0', ipv6='fe80::1', privateDirs=['/var/run','/var/log'], **kwargs)
    sta2 = net.addStation('sta2', mac='02:00:00:00:00:02', ip='10.0.0.2', position='400,100,0', ipv6='fe80::2', privateDirs=['/var/run','/var/log'], **kwargs)
    sta3 = net.addStation('sta3', mac='02:00:00:00:00:03', ip='10.0.0.3', position='450,150,0', ipv6='fe80::3', privateDirs=['/var/run','/var/log'], **kwargs)
    sta4 = net.addStation('sta4', mac='02:00:00:00:00:04', ip='10.0.0.4', position='500,100,0', ipv6='fe80::4', privateDirs=['/var/run','/var/log'], **kwargs)
    sta5 = net.addStation('sta5', mac='02:00:00:00:00:05', ip='10.0.0.5', position='550,150,0', ipv6='fe80::5', privateDirs=['/var/run','/var/log'], **kwargs)
    sta6 = net.addStation('sta6', mac='02:00:00:00:00:06', ip='10.0.0.6', position='600,100,0', ipv6='fe80::6', privateDirs=['/var/run','/var/log'], **kwargs)
    sta7 = net.addStation('sta7', mac='02:00:00:00:00:07', ip='10.0.0.7', position='650,150,0', ipv6='fe80::7', privateDirs=['/var/run','/var/log'], **kwargs)
    sta8 = net.addStation('sta8', mac='02:00:00:00:00:08', ip='10.0.0.8', position='700,100,0', ipv6='fe80::8', privateDirs=['/var/run','/var/log'], **kwargs)

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

    info("*** CONFIGURANDO MOVILIDAD\n")
    net.isReplaying = True
    path = os.path.dirname(os.path.abspath(__file__)) + '/replayingMobility/trayectoria/'
    generar_movilidad(sta1, '{}movilidad_sta1.dat'.format(path))


    if '-p' in args:
        info("*** INICIANDO INTERFAZ GRÁFICA\n")
        net.plotGraph(max_x=1000, max_y=400)


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
    altura = 125
    pasos = 10
    espera = 5
    
    # Posición inicial (fuera de cobertura)
    pos = (150, altura, 0)
    tim = 60
    sta.position = pos
    sta.p.append(pos)
    sta.time.append(tim)

    # Moverse hasta conectar solo con sta2
    for x in range(150, 350, pasos):  # Movimiento en pasos de 5
        pos = (x, altura, 0)
        tim += 1  # Un segundo por cada paso
        sta.p.append(pos)
        sta.time.append(tim)

    


if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)