from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from config import DATABASE_URL

class Base(DeclarativeBase):
    pass

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
@event.listens_for(engine, "connect")
def _sqlite_fk(dbapi_connection, _):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

def init_db():
    from database import models  # noqa: F401
    Base.metadata.create_all(engine)

def get_session():
    return SessionLocal()
