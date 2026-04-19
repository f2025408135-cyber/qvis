import re

with open("backend/main.py", "r") as f:
    content = f.read()

# Update `save_threat` in `simulation_loop`
loop_save_threat = """
                    threat.resolved_at = datetime.now(timezone.utc)
                    await db.resolve_threat(threat.id)
                    logger.info("threat_resolved", threat_id=threat.id)

            for threat in new_threats:
                await db.save_threat(threat)
                logger.info("threat_persisted", threat_id=threat.id)
"""

content = re.sub(
    r'                    threat\.resolved_at = datetime\.now\(timezone\.utc\)\n                    from backend\.storage\.database import resolve_threat\n                    await resolve_threat\(threat\.id\)\n                    logger\.info\("threat_resolved", threat_id=threat\.id\)\n\n            for threat in new_threats:\n                from backend\.storage\.database import save_threat\n                await save_threat\(\n                    id=threat\.id,\n                    technique_id=threat\.technique_id,\n                    severity=str\(threat\.severity\.value if hasattr\(threat\.severity, "value"\) else threat\.severity\),\n                    platform=str\(threat\.platform\.value if hasattr\(threat\.platform, "value"\) else threat\.platform\),\n                    backend_id=threat\.backend_id,\n                    title=threat\.title,\n                    description=threat\.description,\n                    evidence=threat\.evidence,\n                    detected_at=threat\.detected_at\.isoformat\(\) if isinstance\(threat\.detected_at, datetime\) else threat\.detected_at,\n                    visual_effect=threat\.visual_effect,\n                    visual_intensity=threat\.visual_intensity,\n                    remediation=threat\.remediation,\n                \)\n                logger\.info\("threat_persisted", threat_id=threat\.id\)',
    loop_save_threat.strip() + "\n",
    content,
    flags=re.DOTALL
)

with open("backend/main.py", "w") as f:
    f.write(content)
