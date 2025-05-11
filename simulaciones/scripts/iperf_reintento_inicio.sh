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
    iperf3 -c $DESTINO -t 1 > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Conexión exitosa con iPerf3 al servidor $DESTINO. Dejando iPerf3 corriendo..."
        break
    else
        echo "No se pudo conectar con iPerf3 al servidor $DESTINO. Reintentando..."
        sleep 1
    fi
done

# Ejecuta iPerf3 de forma continua
iperf3 -c $DESTINO