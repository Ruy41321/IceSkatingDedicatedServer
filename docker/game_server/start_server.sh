#!/bin/bash

# Script di avvio per il server Godot
echo "Starting Godot Game Server..."

# Crea directory per i log se non esiste
mkdir -p /app/logs

# Crea nome file di log con data corrente
LOG_DATE=$(date +"%Y-%m-%d")
LOG_FILE="/app/logs/server_${LOG_DATE}.log"
echo "Logs will be saved to: $LOG_FILE"

# Avvia il server Godot senza Xvfb se possibile
echo "Starting Godot server on port $SERVER_PORT..."
cd /app/build

# Prova prima senza display (completamente headless)
echo "Attempting to start in headless mode..."
stdbuf -oL -eL ./game_server.x86_64 \
    --server \
    --port=$SERVER_PORT \
    --max-players=$MAX_PLAYERS \
    >> $LOG_FILE 2>&1 &

SERVER_PID=$!

# Controlla se il processo è partito correttamente
sleep 5
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Headless mode failed, trying with virtual display..."
    
    # Crea directory per X11 se non esiste
    mkdir -p /tmp/.X11-unix 2>/dev/null || true
    chmod 1777 /tmp/.X11-unix 2>/dev/null || true
    
    # Imposta le variabili d'ambiente per il server
    export DISPLAY=:99
    
    # Avvia Xvfb per il rendering virtuale
    Xvfb :99 -screen 0 1024x768x24 -ac +extension GLX +render -noreset &
    XVFB_PID=$!
    
    # Attendi che Xvfb sia pronto
    sleep 3
    
    # Riprova con il display virtuale
    stdbuf -oL -eL ./game_server.x86_64 \
		--server \
		--port=$SERVER_PORT \
		--max-players=$MAX_PLAYERS \
		>> $LOG_FILE 2>&1 &
    
    SERVER_PID=$!
    
    # Controlla di nuovo
    sleep 3
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "ERROR: Failed to start Godot server"
        cat $LOG_FILE
        exit 1
    fi
else
    echo "Server started successfully in headless mode"
    XVFB_PID=""
fi

echo "Godot server is running with PID: $SERVER_PID"

# Funzione di cleanup
cleanup() {
    echo "$(date): Server shutting down, cleaning up..." >> $LOG_FILE
    
    # Uccidi Xvfb se in esecuzione
    if [ -n "$XVFB_PID" ] && kill -0 $XVFB_PID 2>/dev/null; then
        kill -15 $XVFB_PID
    fi
    
    echo "$(date): Cleanup completed" >> $LOG_FILE
}

# Imposta trap per gestire la terminazione
trap cleanup SIGINT SIGTERM

# Attendi che il processo termini
echo "$(date): Server running with PID: $SERVER_PID. Waiting for termination..." >> $LOG_FILE
wait $SERVER_PID

# Cleanup
cleanup