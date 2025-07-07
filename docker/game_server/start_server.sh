#!/bin/bash

# Script di avvio per il server Godot
echo "Starting Godot Game Server..."

# Avvia il server Godot senza Xvfb se possibile
echo "Starting Godot server on port $SERVER_PORT..."
cd /app/build

# Prova prima senza display (completamente headless)
echo "Attempting to start in headless mode..."
stdbuf -oL -eL ./game_server.x86_64 \
    --server \
    --port=$SERVER_PORT \
    --max-players=$MAX_PLAYERS \
    >> /app/logs/server.log 2>&1 &

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
		>> /app/logs/server.log 2>&1 &
    
    SERVER_PID=$!
    
    # Controlla di nuovo
    sleep 3
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "ERROR: Failed to start Godot server"
        cat /app/logs/server.log
        exit 1
    fi
else
    echo "Server started successfully in headless mode"
    XVFB_PID=""
fi

echo "Godot server is running with PID: $SERVER_PID"

# Attendi che il processo termini
wait $SERVER_PID

# Cleanup
cleanup