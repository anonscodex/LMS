from collections.abc import AsyncGenerator
import uuid

from sqlalchemy import Column, String, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, relationship, Mapped, mapped_column  # Fixed spelling
from typing import Optional, List
from datetime import datetime
from sqlalchemy import DateTime
from sqlalchemy import String, Text, Integer, Boolean, Float, DateTime, ForeignKey

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
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)  # Add Boolean type
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False) 
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    max_books_allowed: Mapped[int] = mapped_column(Integer, default=5)
    current_books_borrowed: Mapped[int] = mapped_column(Integer, default=0)

    # Use lazy loading with string reference
    borrow_records: Mapped[list["BorrowRecord"]] = relationship(
        "BorrowRecord", 
        back_populates="user",
        lazy="select"  # Add this
    )

     # Use string references for forward declarations

    #borrow_records: Mapped[List["BorrowRecord"]] = relationship("BorrowRecord", back_populates="user")
   #reservations: Mapped[List["Reservation"]] = relationship("Reservation", back_populates="user")
    #fines: Mapped[List["Fine"]] = relationship("Fine", back_populates="user")

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
    total_copies: Mapped[int] = mapped_column(Integer, default=1)  # Should be Integer
    available_copies: Mapped[int] = mapped_column(Integer, default=1)  # Should be Integer, not St
    status: Mapped[str] = mapped_column(String, nullable=False, default="available")

    borrow_records: Mapped[list["BorrowRecord"]] = relationship(
        "BorrowRecord",
        back_populates="book",
        lazy="select"
    )

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


class BorrowRecord(Base):
    __tablename__ = "borrow_records"
    
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    book_id: Mapped[str] = mapped_column(String(36), ForeignKey("books.id", ondelete="CASCADE"), index=True)
    
    borrowed_date: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    due_date: Mapped[datetime] = mapped_column(DateTime)
    returned_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    
    renewal_count: Mapped[int] = mapped_column(Integer, default=0)
    max_renewals: Mapped[int] = mapped_column(Integer, default=2)
    status = Column(String, default="pending_approval")  # Change default
    borrowed_date = Column(DateTime, default=datetime.utcnow)
    due_date = Column(DateTime, nullable=True)  # Make nullable initially
    approved_by = Column(String, nullable=True)  # Who approved/rejected
    approval_notes = Column(Text, nullable=True)  # Notes from admin
    approval_date = Column(DateTime, nullable=True)  # When approved/rejected
    
    # Add these missing columns:
    return_requested_date = Column(DateTime, nullable=True)
    return_approved_by = Column(String, nullable=True)
    return_notes = Column(Text, nullable=True)
    
    user: Mapped["User"] = relationship("User", back_populates="borrow_records")
    book: Mapped["Book"] = relationship("Book", back_populates="borrow_records")
    # Relationships
    #user: Mapped["User"] = relationship("User", back_populates="borrow_records")
   # book: Mapped["Book"] = relationship("Book", back_populates="borrow_records")

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

engine = create_async_engine(DATABASE_URL)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)

async def create_db_and_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)  # Use Base, not DeclarativeBase

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session
    