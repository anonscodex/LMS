from collections.abc import AsyncGenerator
import uuid

from sqlalchemy import Column, String, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column  # Fixed spelling
from typing import Optional
from datetime import datetime
from sqlalchemy import DateTime

# For SQLite, use the built-in UUID support or String
DATABASE_URL = "sqlite+aiosqlite:///./test.db"

class Base(DeclarativeBase):  # Fixed spelling and naming convention
    pass


class User(Base):  # Inherit from Base, not DeclarativeBase directly
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    full_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    student_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    is_admin : Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Book(Base):  # Inherit from Base, not DeclarativeBase directly
    __tablename__ = "books"

    # For SQLite, better to use String for UUID or install sqlite-uuid extension
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    url: Mapped[str] = mapped_column(String, nullable=True)  # Add this line
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(String, nullable=False)
    author: Mapped[str] = mapped_column(String, nullable=False)
    isbn: Mapped[str] = mapped_column(String, nullable=False)
    publisher: Mapped[str] = mapped_column(String, nullable=False)
    publication_year: Mapped[str] = mapped_column(String, nullable=False)
    category: Mapped[str] = mapped_column(String, nullable=False)
    total_copies: Mapped[str] = mapped_column(String, nullable=False)
    available_copies: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="available")

# Alternative with UUID type (if you want to use PostgreSQL dialect features)
# Note: This may not work perfectly with SQLite
# class Book(Base):
#     __tablename__ = "books"
#     
#     id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
#     title = Column(Text)
#     description = Column(String, nullable=False)
#     author = Column(String, nullable=False)
#     status = Column(String, nullable=False, default="available")

engine = create_async_engine(DATABASE_URL)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)

async def create_db_and_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)  # Use Base, not DeclarativeBase

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session
    