from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

# We use SQLite for local testing to avoid requiring a full Postgres installation immediately,
# but this is fully compatible with PostgreSQL when you change the DATABASE_URL.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./atp_backend.db")

# SQLite requires this connect_args, Postgres does not
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
