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
    sta1 = net.addStation('sta1', ip='10.10.0.1/24', mac='02:00:00:00:65:01', position='0,125,0', **kwargs)
    sta2 = net.addStation('sta2', ip='10.10.0.2/24', mac='02:00:00:00:65:02', position='400,100,0', **kwargs)
    sta3 = net.addStation('sta3', ip='10.10.0.3/24', mac='02:00:00:00:65:03', position='450,150,0', **kwargs)
    sta4 = net.addStation('sta4', ip='10.10.0.4/24', mac='02:00:00:00:65:04', position='500,100,0', **kwargs)
    sta5 = net.addStation('sta5', ip='10.10.0.5/24', mac='02:00:00:00:65:05', position='550,150,0', **kwargs)
    sta6 = net.addStation('sta6', ip='10.10.0.6/24', mac='02:00:00:00:65:06', position='600,100,0', **kwargs)
    sta7 = net.addStation('sta7', ip='10.10.0.7/24', mac='02:00:00:00:65:07', position='650,150,0', **kwargs)
    sta8 = net.addStation('sta8', ip='10.10.0.8/24', mac='02:00:00:00:65:08', position='700,100,0', **kwargs)



    

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
    altura = 125
    pasos = 10
    
    # Posición inicial (fuera de cobertura)
    pos = (150, altura, 0)
    tim = 0
    sta.position = pos
    sta.p.append(pos)
    sta.time.append(tim)

    # Moverse hacia (300, 125) hasta conectar solo con sta2
    for x in range(150, 350, pasos):  # Movimiento en pasos de 5
        pos = (x, altura, 0)
        tim += 1  # Un segundo por cada paso
        sta.p.append(pos)
        sta.time.append(tim)

    # Esperar 120 segundos en (300, 125) conectado solo a sta2
    tim += 5
    sta.p.append((350, altura, 0))
    sta.time.append(tim)

    # Continuar el movimiento hasta salir del área (más allá de sta8)
    for x in range(350, 950, pasos):  # Movimiento en pasos de 5
        pos = (x, altura, 0)
        tim += 1  # Un segundo por cada paso
        sta.p.append(pos)
        sta.time.append(tim)

    # Permanecer en la última posición
    sta.p.append((950, altura, 0))
    sta.time.append(tim)


if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)
