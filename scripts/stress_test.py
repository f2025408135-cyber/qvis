import asyncio
import time
import httpx
import websockets
import json

API_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws/simulation"
NUM_REQUESTS = 1000
CONCURRENCY = 100
NUM_WS_CLIENTS = 50

async def fetch_threats(client):
    try:
        start = time.perf_counter()
        response = await client.get(f"{API_URL}/api/threats/history", params={"limit": 50})
        latency = time.perf_counter() - start
        return response.status_code == 200, latency
    except Exception:
        return False, 0.0

async def fetch_snapshot(client):
    try:
        start = time.perf_counter()
        response = await client.get(f"{API_URL}/api/simulation/snapshot")
        latency = time.perf_counter() - start
        return response.status_code == 200, latency
    except Exception:
        return False, 0.0

async def run_api_stress_test():
    print(f"--- Starting API Stress Test: {NUM_REQUESTS} requests, {CONCURRENCY} concurrency ---")
    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=CONCURRENCY)) as client:
        tasks = []
        for i in range(NUM_REQUESTS):
            if i % 2 == 0:
                tasks.append(fetch_threats(client))
            else:
                tasks.append(fetch_snapshot(client))
        
        start_time = time.perf_counter()
        results = await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start_time
    
    success_count = sum(1 for success, _ in results if success)
    latencies = [latency for success, latency in results if success]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    
    print(f"API Stress Test Complete in {total_time:.2f}s")
    print(f"Successful requests: {success_count}/{NUM_REQUESTS}")
    print(f"Average Latency: {avg_latency*1000:.2f}ms")
    print(f"Requests per second: {NUM_REQUESTS/total_time:.2f}")

async def ws_client(client_id, stats):
    try:
        async with websockets.connect(WS_URL) as websocket:
            stats['connected'] += 1
            # Wait for snapshot
            msg = await websocket.recv()
            stats['messages_received'] += 1
            
            # Keep alive and receive updates
            start_time = time.time()
            while time.time() - start_time < 10: # Listen for 10 seconds
                try:
                    msg = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    stats['messages_received'] += 1
                except asyncio.TimeoutError:
                    continue
    except Exception as e:
        stats['errors'] += 1

async def run_ws_stress_test():
    print(f"--- Starting WebSocket Stress Test: {NUM_WS_CLIENTS} clients ---")
    stats = {'connected': 0, 'messages_received': 0, 'errors': 0}
    
    tasks = [ws_client(i, stats) for i in range(NUM_WS_CLIENTS)]
    start_time = time.perf_counter()
    await asyncio.gather(*tasks)
    total_time = time.perf_counter() - start_time
    
    print(f"WebSocket Stress Test Complete in {total_time:.2f}s")
    print(f"Successfully connected clients: {stats['connected']}/{NUM_WS_CLIENTS}")
    print(f"Total messages received: {stats['messages_received']}")
    print(f"Errors: {stats['errors']}")

async def main():
    # Warm up
    print("Warming up API...")
    async with httpx.AsyncClient() as client:
        await client.get(f"{API_URL}/api/simulation/snapshot")
    
    await run_api_stress_test()
    print("\n")
    await run_ws_stress_test()

if __name__ == "__main__":
    asyncio.run(main())
