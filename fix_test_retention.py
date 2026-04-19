import re

with open("tests/test_retention.py", "r") as f:
    content = f.read()

# Let's wait slightly longer since it sleeps for `0.0001 * 3600` = `0.36` seconds!
content = content.replace("asyncio.create_task(retention_loop(db, 30, 0.0001))", "asyncio.create_task(retention_loop(db, 30, 0.000001))")
content = content.replace("await asyncio.sleep(0.0005)", "await asyncio.sleep(0.05)")

with open("tests/test_retention.py", "w") as f:
    f.write(content)
