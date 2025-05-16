#!/bin/bash

# Verifica si se proporcionó un destino como parámetro
if [ -z "$1" ]; then
    echo "Error: Debes proporcionar un destino (IP o dominio) como parámetro."
    echo "Uso: $0 <destino>"
    exit 1
fi

DESTINO="$1"  # Usa el primer parámetro como destino

echo "Intentando conectar con iPerf3 al servidor $DESTINO..."

# Reintenta hasta que el primer intento de conexión sea exitoso
while true; do
    iperf -u -c $DESTINO -t 9999999999999999999
    if [ $? -eq 0 ]; then
        echo "iPerf3 ha concluido correctamente al conectarse al servidor $DESTINO."
        break
    else
        sleep 1
    fi
done