#!/bin/bash

# Verifica si se proporcionó un destino como parámetro
if [ -z "$1" ]; then
    echo "Error: Debes proporcionar un destino (IP o dominio) como parámetro."
    echo "Uso: $0 <destino>"
    exit 1
fi

DESTINO="$1"  # Usa el primer parámetro como destino

echo "Intentando conectar con iPerf3 al servidor $DESTINO..."

# Ejecuta en bucle infinito
while true; do
    iperf -c $DESTINO -t 0
done