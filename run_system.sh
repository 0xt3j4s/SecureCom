#!/bin/bash

# Start the server in the background and redirect output to server.log
python3 server.py &> server.log &

# Wait for the server to start up
sleep 2

# Connect to the server and start the client, and redirect output to client.log
python3 client.py &> client.log

# Kill the server process
kill $(ps aux | grep '[s]erver.py' | awk '{print $2}')
