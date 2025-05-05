#!/bin/bash

SERVER_IP="10.0.0.2"
SERVER_PORT=5201
DURATION=10             # Duración del test de iperf3
MAX_TIEMPO_TOTAL=15     # Tiempo máximo total permitido por test (corte forzado)
PAUSA_ENTRE_TESTS=1     # Tiempo de espera entre intentos

while true; do
  echo "[$(date)] Iniciando test con $SERVER_IP:$SERVER_PORT"

  timeout "$MAX_TIEMPO_TOTAL" iperf3 -c "$SERVER_IP" -p "$SERVER_PORT" -t "$DURATION"
  
  if [[ $? -ne 0 ]]; then
    echo "[$(date)] Fallo, timeout o interrupción detectada. Reintentando en $PAUSA_ENTRE_TESTS s..."
  else
    echo "[$(date)] Test completado correctamente."
  fi

  sleep "$PAUSA_ENTRE_TESTS"
done
