import re

with open("backend/config.py", "r") as f:
    content = f.read()

# Modify configuration.
# Instructions say:
# threat_retention_days: int = 30
# retention_check_interval_hours: int = 6
# Let's replace the old retention configuration
replacement = """    # Data Retention — controls automatic cleanup of old records.
    threat_retention_days: int = Field(
        default=30,
        ge=1,
        le=3650,
        description="Days to retain resolved threat events before purging.",
    )
    retention_check_interval_hours: int = Field(
        default=6,
        ge=1,
        le=720,
        description="Hours between automatic retention cleanup cycles.",
    )"""

content = re.sub(r'    # Data Retention — controls automatic cleanup of old records\..*?description="Whether to run VACUUM after cleanup \(SQLite only\)\.",\n    \)', replacement, content, flags=re.DOTALL)

with open("backend/config.py", "w") as f:
    f.write(content)

