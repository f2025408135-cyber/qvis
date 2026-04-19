import os

# Delete old migrations and use our new schema instead of having duplicates.
files = os.listdir("alembic/versions")
for file in files:
    if "0001_initial_schema" in file or "0002_add_resolved_at_to_correlations" in file:
        os.remove(f"alembic/versions/{file}")
