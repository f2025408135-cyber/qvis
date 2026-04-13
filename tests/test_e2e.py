import pytest
import os
import tempfile
import sys
import subprocess
import time
import requests

try:
    from playwright.sync_api import sync_playwright
    has_playwright = True
except ImportError:
    has_playwright = False

@pytest.mark.e2e
@pytest.mark.skipif(not has_playwright, reason="Playwright is required for E2E tests")
def test_qvis_cinematic_mode():
    def run_cuj(page, temp_dir):
        print("Navigating to QVis Cinematic Mode...")
        page.goto("http://localhost:3000")
        
        # Wait for initial cinematic load
        page.wait_for_timeout(4000)
        
        print("Opening Threat Panel & Triggering Fly-In...")
        page.evaluate("if(document.querySelector('.threat-tag')) document.querySelector('.threat-tag').click();")
        
        # Wait for fly-in tween to finish
        page.wait_for_timeout(2500)
        
        print("Taking screenshot of Hollywood UI & Post-Processing...")
        screenshot_path = os.path.join(temp_dir, "cinematic_stress_test.png")
        page.screenshot(path=screenshot_path)
        
        print("Recording animations (Bloom, Tween, Shaders)...")
        page.wait_for_timeout(6000)

    # In a real environment, we'd start the server here dynamically 
    # using subprocess, but since pytest may already be running the server externally 
    # we'll just check if it's up, otherwise start it temporarily.
    
    server_process = None
    frontend_process = None
    
    try:
        requests.get("http://localhost:8000/api/health")
    except requests.exceptions.ConnectionError:
        server_process = subprocess.Popen(["uvicorn", "backend.main:app", "--port", "8000"])
        time.sleep(2)

    try:
        requests.get("http://localhost:3000/")
    except requests.exceptions.ConnectionError:
        frontend_process = subprocess.Popen(["python", "-m", "http.server", "3000", "--directory", "frontend"])
        time.sleep(2)

    with tempfile.TemporaryDirectory() as temp_dir:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                record_video_dir=temp_dir,
                record_video_size={"width": 1280, "height": 720}
            )
            page = context.new_page()
            try:
                run_cuj(page, temp_dir)
            finally:
                context.close()
                browser.close()

    if server_process:
        server_process.terminate()
    if frontend_process:
        frontend_process.terminate()

