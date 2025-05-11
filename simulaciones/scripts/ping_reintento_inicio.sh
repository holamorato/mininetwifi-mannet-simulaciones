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
    ping $DESTINO
    if [ $? -eq 0 ]; then
        echo "Ping exitoso a $DESTINO ha concluido."
        break
    else
        sleep 1
    fi
done