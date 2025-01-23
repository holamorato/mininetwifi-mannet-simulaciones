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
    num_nodos = 5
    kwargs = {}
    protocols = ['batman_adv', 'olsrd', 'olsrd2']
    for proto in args:
        if proto in protocols:
            kwargs['proto'] = proto
    if 'proto' not in kwargs:
        info("*ERROR: No ha elegido un protocolo entre: batman_adv, olsrd, olsrd2\n")
        exit()

    # Generación Semilla Aleatoria
    seed = 2016
    random.seed(seed)

    # Creación de las características de la red
    info("*** CREACION DE LA RED\n")
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)
    net.setPropagationModel(model="logDistance", exp=4)


    # Configuración de la topología de red

    info("*** CONFIGURACION DE TOPOLOGIA\n")
    info("*** Añadiendo nodos a la red\n")
    sta1 = net.addStation('sta1', ip='10.10.0.1/24', mac='02:00:00:00:65:01', position='300,300,0', **kwargs)
    sta2 = net.addStation('sta2', ip='10.10.0.2/24', mac='02:00:00:00:65:02', position='370,370,0', **kwargs)
    sta3 = net.addStation('sta3', ip='10.10.0.3/24', mac='02:00:00:00:65:03', position='440,370,0', **kwargs)
    sta4 = net.addStation('sta4', ip='10.10.0.4/24', mac='02:00:00:00:65:04', position='510,380,0', **kwargs)
    sta10 = net.addStation('sta10', ip='10.10.0.10/24', mac='02:00:00:00:65:05', position='500,100,0', **kwargs)

    info("*** Configurando nodos Wifi\n")
    net.configureWifiNodes()

    info("*** Añadiendo enlaces inalámbricos\n")
    net.addLink(sta1, cls=adhoc, intf='sta1-wlan0', ssid='adhocNet', mode='g', channel=5, **kwargs)
    net.addLink(sta2, cls=adhoc, intf='sta2-wlan0', ssid='adhocNet', mode='g', channel=5, **kwargs)
    net.addLink(sta3, cls=adhoc, intf='sta3-wlan0', ssid='adhocNet', mode='g', channel=5, **kwargs)
    net.addLink(sta4, cls=adhoc, intf='sta4-wlan0', ssid='adhocNet', mode='g', channel=5, **kwargs)
    net.addLink(sta10, cls=adhoc, intf='sta10-wlan0', ssid='adhocNet', mode='g', channel=5, **kwargs)

    info("*** CONFIGURANDO MOVILIDAD\n")
    net.isReplaying = True
    path = os.path.dirname(os.path.abspath(__file__)) + '/replayingMobility/trayectoria/'
    generar_movilidad(sta10, '{}movilidad_sta10.dat'.format(path))


    if '-p' in args:
        info("*** INICIANDO INTERFAZ GRÁFICA\n")
        net.plotGraph(max_x=800, max_y=800)


    info("*** CONSTRUYENDO RED\n")
    net.build()

    info("\n*** INICIANDO MOVILIDAD\n")
    ReplayingMobility(net)

    info("*** INICIANDO CONSOLA DE COMANDOS\n")
    CLI(net)


    info("*** PARANDO RED\n")
    net.stop()



# # FUNCIONES PARA XTERM
# def start_batmand_xterm(net):
#     """Inicia batmand en cada estación y lo muestra en un xterm."""
#     for sta in net.stations:
#         sta.cmd(f'xterm -hold -e "bash -c \'batmand {sta.name}-wlan0 & '
#                 f'sleep 5; ps aux | grep batman --color=auto; '
#                 f'batmand -c -d 1; exec bash\'" &')

# def show_ifconfig_xterm(net):
#     """Abre un xterm en cada estación y muestra ifconfig."""
#     for sta in net.stations:
#         sta.cmd(f'xterm -hold -e "bash -c \'ifconfig; exec bash\'" &')

# def show_processes_xterm(net):
#     """Abre un xterm en cada estación y muestra los procesos en entorno de usuario."""
#     for sta in net.stations:
#         sta.cmd(f'xterm -hold -e "bash -c \'ps aux; exec bash\'" &')

# def show_batman_processes_xterm(net):
#     """Abre un xterm en cada estación y muestra solo los procesos relacionados con batman."""
#     for sta in net.stations:
#         sta.cmd(f'xterm -hold -e "bash -c \'ps aux | grep [b]atman --color=auto; exec bash\'" &')




def generar_movilidad(sta, file_):
    sta.p = []
    sta.time = []
    
    # Posición inicial
    pos = (250, 700, 0)
    tim = 0
    sta.position = pos
    sta.p.append(pos)
    sta.time.append(tim)
    
    # Moverse a (250, 300) 4 veces más rápido
    for y in range(700, 299, -1):
        pos = (250, y, 0)
        tim += 0.25  # Asumiendo 0.25 segundos por paso para 4 veces más rápido
        sta.p.append(pos)
        sta.time.append(tim)
    
    # Esperar 30 segundos
    tim += 30
    sta.p.append((250, 300, 0))
    sta.time.append(tim)
    
    # Moverse de vuelta a (250, 700)
    for y in range(300, 701, 1):
        pos = (250, y, 0)
        tim += 0.25  # Asumiendo 0.25 segundos por paso para 4 veces más rápido
        sta.p.append(pos)
        sta.time.append(tim)
    
    # Permanecer en (250, 700)
    sta.p.append((250, 700, 0))
    sta.time.append(tim)

if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)
