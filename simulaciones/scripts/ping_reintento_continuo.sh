#!/bin/bash

# Verifica si se proporcionó un destino como parámetro
if [ -z "$1" ]; then
    echo "Error: Debes proporcionar un destino (IP o dominio) como parámetro."
    echo "Uso: $0 <destino>"
    exit 1
fi

DESTINO="$1"  # Usa el primer parámetro como destino

echo "Intentando hacer ping a $DESTINO..."

# Reintenta hasta que el primer ping sea exitoso
while true; do
    ping -c 1 $DESTINO > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Primer ping exitoso a $DESTINO. El script ha hecho su trabajo."
        break
    else
        echo "No hay ruta disponible para el ping a $DESTINO. Reintentando..."
        sleep 1
    fi
done