with open("requirements.txt", "r") as f:
    content = f.read()

if "asyncpg" not in content:
    content += "\nalembic>=1.13.0\nasyncpg>=0.29.0\nsqlalchemy[asyncio]>=2.0\n"

with open("requirements.txt", "w") as f:
    f.write(content)

with open(".env.example", "r") as f:
    content = f.read()

if "DB_POOL_SIZE" not in content:
    content += "\nDATABASE_URL=sqlite:///./data/qvis.db\n# For PostgreSQL:\n# DATABASE_URL=postgresql://qvis:password@localhost:5432/qvis\nDB_POOL_SIZE=10\n"

with open(".env.example", "w") as f:
    f.write(content)
