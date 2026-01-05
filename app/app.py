from fastapi import FastAPI, HTTPException, Depends, File, Form, UploadFile, status
from app.schemas import uploadBook, uploadResponse, updateBook, updateResponse, UserRegister, UserResponse, UserProfileResponse, AdminRegisterRequest, AdminRegisterResponse
from app.db import Book, User, create_db_and_tables, get_async_session 
from sqlalchemy.ext.asyncio import AsyncSession
from contextlib import asynccontextmanager
from sqlalchemy import select

import uuid
from passlib.context import CryptContext
import hashlib
import re
from datetime import datetime, timedelta
from app.images import imagekit, URL_ENDPOINT, PUBLIC_KEY
from app.db import User, get_async_session
from app.auth import ACCESS_TOKEN_EXPIRE_MINUTES,SECRET_KEY, ALGORITHM, verify_password, create_access_token, hash_password
from app.schemas import LoginRequest, Token, UserLoginResponse
from fastapi.security import OAuth2PasswordBearer   , OAuth2PasswordRequestForm
from jose import JWTError, jwt

import shutil
import os
import tempfile

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Switch to Argon2
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],  # Try Argon2 first, fallback to bcrypt
    deprecated="auto"
)
# Password hashing context
def hash_password(password: str) -> str:
    """Hash a password using Argon2 (no 72-byte limit)"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)






@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_db_and_tables()
    yield

app = FastAPI(lifespan=lifespan)


# ========== AUTH DEPENDENCIES (Define these FIRST) ==========

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_async_session)
):
    """Get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if user is None:
        raise credentials_exception
    
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    """Get current active user"""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# ========== PUBLIC ENDPOINTS ==========

# Admin registration endpoint using Pydantic model
@app.post("/admin/register", response_model=AdminRegisterResponse)
async def register_admin(
    admin_data: AdminRegisterRequest,  # Use Pydantic model instead of Form fields
    session: AsyncSession = Depends(get_async_session)
):
    """Register an admin user (requires secret key)"""
    
    # Check admin secret key from environment variables
    ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY")
    if not ADMIN_SECRET_KEY:
        # Fallback for development (remove in production)
        ADMIN_SECRET_KEY = "dev-admin-secret-2024"
    
    if admin_data.secret_key != ADMIN_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin secret key"
        )
    
    # Check if user already exists by email
    existing_email = await session.execute(
        select(User).where(User.email == admin_data.email)
    )
    if existing_email.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Check if username already exists
    existing_username = await session.execute(
        select(User).where(User.username == admin_data.username)
    )
    if existing_username.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    # Create admin user
    user = User(
        email=admin_data.email,
        username=admin_data.username,
        full_name=admin_data.full_name,
        hashed_password=hash_password(admin_data.password),
        is_admin=True,  # Set admin flag
        is_active=True,
        student_id=f"ADMIN-{admin_data.username.upper()}"  # Generate admin student ID
    )
    
    session.add(user)
    await session.commit()
    await session.refresh(user)
    
    return AdminRegisterResponse(
        message="Admin user created successfully",
        user_id=user.id,
        email=user.email,
        username=user.username,
        is_admin=user.is_admin,
        created_at=user.created_at.isoformat() if user.created_at else None
    )


@app.post("/register", response_model=UserResponse)
async def register_user(
    user_data: UserRegister,  # Use Pydantic model instead of individual Form fields
    session: AsyncSession = Depends(get_async_session)
):
    # Check existing users
    existing_user = await session.execute(
        select(User).where(
            (User.email == user_data.email) | 
            (User.username == user_data.username) |
            (User.student_id == user_data.student_id if user_data.student_id else False)
        )
    )
    if existing_user.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create new user
    user = User(
        email=user_data.email,
        username=user_data.username,
        full_name=user_data.full_name,
        hashed_password=hash_password(user_data.password),
        student_id=user_data.student_id,
        created_at=datetime.utcnow()
    )
    
    session.add(user)
    await session.commit()
    await session.refresh(user)
    
    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "full_name": user.full_name,
        "student_id": user.student_id,
        "created_at": user.created_at.isoformat() if user.created_at else None
    }

@app.post("/upload", response_model=uploadResponse)
async def upload_book(
    file: UploadFile = File(...),
    title: str = Form(...),
    description: str = Form(...),
    isbn: str = Form(...),
    author: str = Form(...),
    publisher: str = Form(...),
    publication_year: str = Form(...),
    category: str = Form(...),
    total_copies: str = Form(...),
    available_copies: str = Form(...),
    status: str = Form(default="available"),
    session: AsyncSession = Depends(get_async_session)
): 
    temp_file_path = None

    try:
        file_extension = os.path.splitext(file.filename)[1]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_extension) as temp_file:
            temp_file_path = temp_file.name
            content = await file.read()
            temp_file.write(content)

        # Upload to ImageKit
        upload_result = imagekit.files.upload(
            file=open(temp_file_path, "rb"),
            file_name=file.filename,
            use_unique_file_name=True, 
            tags=["backend-upload"]
        )

        # Debug: Check what attributes the response has
        print("Upload result type:", type(upload_result))
        print("Upload result attributes:", dir(upload_result))
        
        # Check if upload was successful
        if hasattr(upload_result, 'error'):
            if upload_result.error:
                raise HTTPException(status_code=500, detail=f"ImageKit error: {upload_result.error}")
        
        # Check for status code or successful response
        if hasattr(upload_result, 'status_code'):
            if upload_result.status_code == 200:
                # Success - create book
                pass
        elif hasattr(upload_result, 'response_metadata'):
            # Check response_metadata attribute
            if upload_result.response_metadata.http_status_code == 200:
                # Success - create book
                pass
        elif hasattr(upload_result, 'url'):
            # If there's a URL, assume success
            # Success - create book
            pass
        else:
            # Couldn't determine success
            raise HTTPException(status_code=500, detail="Unknown upload response format")

        # Generate UUID for the book
        book_id = str(uuid.uuid4())
        
        # Get the URL from the response
        image_url = getattr(upload_result, 'url', 'https://example.com/default.jpg')
        
        book = Book(
            id=book_id,
            url=image_url,
            title=title,
            description=description,
            author=author,
            isbn=isbn,
            publisher=publisher,
            publication_year=publication_year,
            category=category,
            total_copies=total_copies,
            available_copies=available_copies,
            status=status
        ) 
        session.add(book)
        await session.commit()
        await session.refresh(book)
        return book

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
        await file.close()

@app.get("/allusers")
async def get_all_users(
    session: AsyncSession = Depends(get_async_session)
):
    result = await session.execute(select(User))
    users = result.scalars().all()  # Use scalars() to get User objects directly

    users_data = []
    for user in users:
        users_data.append(
            {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "full_name": user.full_name,
                "student_id": user.student_id,
                "created_at": user.created_at.isoformat() if user.created_at else None
            }
        )

    return {"users": users_data}

@app.get("/allbooks")
async def get_all_books(  
    session: AsyncSession = Depends(get_async_session)
):
    result = await session.execute(select(Book))
    books = result.scalars().all()  # Use scalars() to get Book objects directly
    
    books_data = []
    for book in books:
        books_data.append(
            {
                "id": str(book.id),
                "url": book.url if book.url else None,
                "title": book.title,
                "description": book.description,
                "author": book.author,
                "isbn":book.isbn,
                "publisher":book.publisher,
                "publication_year":book.publication_year,
                "category":book.category,
                "total_copies":book.total_copies,
                "available_copies":book.available_copies,
                "status": book.status
            }
        )
    
    return {"books": books_data}

@app.get("/books/{book_id}")
async def get_book_by_id(
    book_id: str,
    session: AsyncSession = Depends(get_async_session)
):
    result = await session.execute(
        select(Book).where(Book.id == book_id)
    )
    book = result.scalar_one_or_none()
    
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    return {
        "id": str(book.id),
        "url": book.url if book.url else None,
        "title": book.title,
        "description": book.description,
        "author": book.author,
        "status": book.status
    }

@app.patch("/books/{book_id}", response_model=updateResponse)
async def update_book_by_id(
    book_id: str,  
    book_data: updateBook,  
    session: AsyncSession = Depends(get_async_session)
):
    # fetch the existing book
    result = await session.execute(
        select(Book).where(Book.id == book_id)
    )
    book = result.scalar_one_or_none()
    
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    
    update_dict = book_data.dict(exclude_unset=True)
    for key, value in update_dict.items():
        setattr(book, key, value)
    
    await session.commit()
    await session.refresh(book)
    
    return {
        "message": "Book updated successfully",
        "book": {
            "id": str(book.id),
            "url": book.url if book.url else None,
                "title": book.title,
                "description": book.description,
                "author": book.author,
                "isbn":book.isbn,
                "publisher":book.publisher,
                "publication_year":book.publication_year,
                "category":book.category,
                "total_copies":book.total_copies,
                "available_copies":book.available_copies,
                "status": book.status
        }
    }


@app.post("/login", response_model=UserLoginResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_async_session)
):
    """User login endpoint"""
    # Try to find user by username or email
    user = None
    
    # Check if input is email
    if "@" in form_data.username:
        # Search by email
        result = await session.execute(
            select(User).where(User.email == form_data.username)
        )
        user = result.scalar_one_or_none()
    else:
        # Search by username
        result = await session.execute(
            select(User).where(User.username == form_data.username)
        )
        user = result.scalar_one_or_none()
    
    # User not found
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    # Verify password
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.id, "username": user.username},
        expires_delta=access_token_expires
    )
    
    # Return user info with token
    return UserLoginResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        student_id=user.student_id,
        is_admin=user.is_admin,
        max_books_allowed=getattr(user, 'max_books_allowed', 500),  # Default to 5 if not exists
        access_token=access_token,
        token_type="bearer"
    )


# Protected endpoint example
@app.get("/users/me", response_model=UserProfileResponse)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """Get current user profile"""
    return current_user

@app.get("/users/me/borrowed-books")
async def get_my_borrowed_books(
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Get books borrowed by current user"""
    from app.db import BorrowRecord, Book
    from sqlalchemy.orm import selectinload
    
    result = await session.execute(
        select(BorrowRecord)
        .options(selectinload(BorrowRecord.book))
        .where(
            BorrowRecord.user_id == current_user.id,
            BorrowRecord.status == "borrowed"
        )
        .order_by(BorrowRecord.due_date)
    )
    
    borrowed_records = result.scalars().all()
    
    books = []
    for record in borrowed_records:
        books.append({
            "book_id": record.book.id,
            "title": record.book.title,
            "author": record.book.author,
            "borrowed_date": record.borrowed_date,
            "due_date": record.due_date,
            "renewal_count": record.renewal_count
        })
    
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "borrowed_books_count": len(books),
        "borrowed_books": books
    }