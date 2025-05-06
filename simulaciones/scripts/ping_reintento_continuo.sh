#!/bin/bash

# Verifica si se proporcionó un destino como parámetro
if [ -z "$1" ]; then
    echo "Error: Debes proporcionar un destino (IP o dominio) como parámetro."
    echo "Uso: $0 <destino>"
    exit 1
fi

DESTINO="$1"  # Usa el primer parámetro como destino

echo "Intentando hacer ping a $DESTINO..."
contador=0  # Inicializa el contador

while true; do
    ping -c 1 $DESTINO > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Ping $((contador += 1)) exitoso a $DESTINO"
        sleep 1
    else
        echo "No hay ruta disponible para el ping $((contador += 1)) a $DESTINO. Reintentando..."
        sleep 1
    fi
done