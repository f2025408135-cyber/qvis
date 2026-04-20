import asyncio
import time
import httpx
import websockets
import json
import statistics

API_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000/ws/simulation"
NUM_REQUESTS = 2000
CONCURRENCY = 200
NUM_WS_CLIENTS = 150 # Targeting near the MAX_CONNECTIONS limit (200)

stats = {
    'api': {'success': 0, 'failed': 0, '429': 0, '401': 0, 'latencies': []},
    'ws': {'connected': 0, 'messages_received': 0, 'errors': 0, 'disconnects': 0}
}

async def fetch_endpoint(client, url, method="GET", json_data=None, headers=None):
    try:
        start = time.perf_counter()
        if method == "GET":
            response = await client.get(url, headers=headers)
        elif method == "POST":
            response = await client.post(url, json=json_data, headers=headers)
        latency = time.perf_counter() - start
        
        status = response.status_code
        if status == 200:
            stats['api']['success'] += 1
            stats['api']['latencies'].append(latency)
        elif status == 429:
            stats['api']['429'] += 1
        elif status == 401:
            stats['api']['401'] += 1
        else:
            stats['api']['failed'] += 1
            
        return status, latency
    except Exception as e:
        stats['api']['failed'] += 1
        return None, 0.0

async def run_api_stress_test():
    print(f"--- [PHASE 1] API Exhaustive Stress Test: {NUM_REQUESTS} requests, {CONCURRENCY} concurrency ---")
    
    endpoints = [
        (f"{API_URL}/health", "GET", None),
        (f"{API_URL}/api/threats/history?limit=100", "GET", None),
        (f"{API_URL}/api/simulation/snapshot", "GET", None),
        (f"{API_URL}/api/threats/stats", "GET", None),
        (f"{API_URL}/api/admin/retention/run", "POST", None) # Will 401 without auth, which is correct
    ]
    
    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=CONCURRENCY), timeout=10.0) as client:
        tasks = []
        for i in range(NUM_REQUESTS):
            url, method, data = endpoints[i % len(endpoints)]
            tasks.append(fetch_endpoint(client, url, method, data))
        
        start_time = time.perf_counter()
        await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start_time
    
    latencies = stats['api']['latencies']
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    p95_latency = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else 0
    
    print(f"API Stress Test Complete in {total_time:.2f}s")
    print(f"Successful (200): {stats['api']['success']}")
    print(f"Rate Limited (429): {stats['api']['429']} (Expected if RateLimiter works)")
    print(f"Unauthorized (401): {stats['api']['401']} (Expected for admin routes)")
    print(f"Failed (Other): {stats['api']['failed']}")
    print(f"Average Latency: {avg_latency*1000:.2f}ms")
    print(f"P95 Latency: {p95_latency*1000:.2f}ms")
    print(f"Requests per second: {NUM_REQUESTS/total_time:.2f}\n")

async def ws_client(client_id):
    try:
        async with websockets.connect(WS_URL, open_timeout=5.0) as websocket:
            stats['ws']['connected'] += 1
            # Keep alive and receive updates for 15 seconds
            start_time = time.time()
            while time.time() - start_time < 15:
                try:
                    msg = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                    stats['ws']['messages_received'] += 1
                except asyncio.TimeoutError:
                    continue
                except websockets.exceptions.ConnectionClosed:
                    stats['ws']['disconnects'] += 1
                    break
    except websockets.exceptions.InvalidStatusCode as e:
        if e.status_code == 429:
             stats['api']['429'] += 1
        else:
             stats['ws']['errors'] += 1
    except Exception as e:
        stats['ws']['errors'] += 1

async def run_ws_stress_test():
    print(f"--- [PHASE 2] WebSocket Concurrency Stress Test: {NUM_WS_CLIENTS} simultaneous clients ---")
    
    tasks = [ws_client(i) for i in range(NUM_WS_CLIENTS)]
    start_time = time.perf_counter()
    await asyncio.gather(*tasks)
    total_time = time.perf_counter() - start_time
    
    print(f"WebSocket Stress Test Complete in {total_time:.2f}s")
    print(f"Peak Connected clients: {stats['ws']['connected']}/{NUM_WS_CLIENTS}")
    print(f"Disconnects mid-flight: {stats['ws']['disconnects']}")
    print(f"Total messages pushed to clients: {stats['ws']['messages_received']}")
    print(f"Connection Errors: {stats['ws']['errors']}\n")

async def main():
    try:
        async with httpx.AsyncClient() as client:
            await client.get(f"{API_URL}/health")
    except Exception:
        print("Backend not reachable. Ensure it's running on port 8000.")
        return

    await run_api_stress_test()
    await run_ws_stress_test()

if __name__ == "__main__":
    asyncio.run(main())
