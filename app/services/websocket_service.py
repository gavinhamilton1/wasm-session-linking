import asyncio
import random
import websockets

# List to keep track of connected clients
connected_clients = set()

async def broadcast_random_number():
    while True:
        # Generate a random number
        random_number = random.randint(1, 1000000)
        # Broadcast the random number to all connected clients
        if connected_clients:  # Only send if there are connected clients
            await asyncio.wait([client.send(str(random_number)) for client in connected_clients])
        # Wait for 5 seconds before sending the next number
        await asyncio.sleep(5)

async def handler(websocket, path):
    # Register the new client
    connected_clients.add(websocket)
    try:
        # Keep the connection open
        await websocket.wait_closed()
    finally:
        # Unregister the client on disconnect
        connected_clients.remove(websocket)

async def main():
    # Start the WebSocket server
    async with websockets.serve(handler, "localhost", 8765):
        # Start broadcasting random numbers
        await broadcast_random_number()

# Run the server
asyncio.run(main()) 