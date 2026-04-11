from playwright.sync_api import sync_playwright

def run_cuj(page):
    print("Navigating to QVis Cinematic Mode...")
    page.goto("http://localhost:3000")
    
    # Wait for initial cinematic load
    page.wait_for_timeout(4000)
    
    print("Opening Threat Panel & Triggering Fly-In...")
    page.evaluate("if(document.querySelector('.threat-tag')) document.querySelector('.threat-tag').click();")
    
    # Wait for fly-in tween to finish
    page.wait_for_timeout(2500)
    
    print("Taking screenshot of Hollywood UI & Post-Processing...")
    page.screenshot(path="/home/jules/verification/screenshots/cinematic_stress_test.png")
    
    print("Recording animations (Bloom, Tween, Shaders)...")
    page.wait_for_timeout(6000)

if __name__ == "__main__":
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            record_video_dir="/home/jules/verification/videos",
            record_video_size={"width": 1280, "height": 720}
        )
        page = context.new_page()
        try:
            run_cuj(page)
        finally:
            context.close()
            browser.close()
