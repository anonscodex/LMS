from fastapi import FastAPI, HTTPException, Depends, File, Form, UploadFile, status
from app.schemas import uploadBook, uploadResponse, updateBook, updateResponse, UserRegister, UserResponse, UserProfileResponse, AdminRegisterRequest, AdminRegisterResponse, BorrowRequest, BorrowResponse
from app.db import Book, User, BorrowRecord, create_db_and_tables, get_async_session 
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


async def get_current_admin_user(current_user: User = Depends(get_current_active_user)):
    """Check if current user is admin"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required. Only administrators can perform this action."
        )
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


@app.post("/upload", response_model=uploadResponse)  # Your response model
async def upload_book(
    # Current user must be admin
    current_user: User = Depends(get_current_admin_user),
    
    # File upload
    file: UploadFile = File(...),
    
    # Book details
    title: str = Form(...),
    description: str = Form(...),
    author: str = Form(...),
    isbn: str = Form(default=""),
    publisher: str = Form(default=None),
    publication_year: int = Form(default=None),  # Change to int
    category: str = Form(default=None),
    total_copies: int = Form(default=1),  # Change to int
    status: str = Form(default="available"),
    
    # Database session
    session: AsyncSession = Depends(get_async_session)
): 
    """Upload a new book (Admin only)"""
    
    # Log who is uploading
    print(f"Admin {current_user.username} is uploading a book: {title}")
    
    temp_file_path = None

    try:
        # Check if book with same ISBN already exists
        if isbn:
            existing_book = await session.execute(
                select(Book).where(Book.isbn == isbn)
            )
            if existing_book.scalar_one_or_none():
                raise HTTPException(
                    status_code=400,
                    detail=f"Book with ISBN {isbn} already exists"
                )
        
        # Handle file upload to ImageKit
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
            tags=["library-upload", f"uploaded-by-{current_user.username}"]
        )

        if not hasattr(upload_result, 'url') or not upload_result.url:
            raise HTTPException(status_code=500, detail="Image upload failed")

        # Generate UUID for the book
        book_id = str(uuid.uuid4())
        
        # Create book
        book = Book(
            id=book_id,
            url=upload_result.url,
            title=title,
            description=description,
            author=author,
            isbn=isbn if isbn else None,
            publisher=publisher,
            publication_year=publication_year,
            category=category,
            total_copies=total_copies,
            available_copies=total_copies,  # All copies available initially
            status=status,
            
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


# ========== AUTH DEPENDENCIES ==========

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
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
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

async def get_current_admin_user(current_user: User = Depends(get_current_active_user)):
    """Check if current user is admin"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required. Only administrators can perform this action."
        )
    return current_user

# ========== PROTECTED ENDPOINTS delete ==========


@app.delete("/books/{book_id}")
async def delete_book(
    book_id: str,
    current_user: User = Depends(get_current_admin_user),  # Admin only
    session: AsyncSession = Depends(get_async_session)
):
    """Delete a book (Admin only)"""
    result = await session.execute(
        select(Book).where(Book.id == book_id)
    )
    book = result.scalar_one_or_none()
    
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    await session.delete(book)
    await session.commit()
    
    return {"message": f"Book '{book.title}' deleted successfully"}

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
    book_data: updateBook,  # This should be defined in schemas.py, not here
    current_user: User = Depends(get_current_admin_user),  # Admin only
    session: AsyncSession = Depends(get_async_session)
):
    # Fetch the existing book
    result = await session.execute(
        select(Book).where(Book.id == book_id)
    )
    book = result.scalar_one_or_none()
    
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    # Update only the fields that are provided in the request
    update_dict = book_data.dict(exclude_unset=True)
    for key, value in update_dict.items():
        if value is not None:  # Don't update with None values
            setattr(book, key, value)
    
    await session.commit()
    await session.refresh(book)
    
    return {
        "message": "Book updated successfully",
        "book": book  # Let FastAPI convert using updateResponse model
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
        max_books_allowed=getattr(user, 'max_books_allowed', 5),  # Default to 5 if not exists
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
    """Get current user's borrowed books - NO relationships"""
    
    # Get borrow records for this user
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.user_id == current_user.id,
            BorrowRecord.status == "borrowed"
        ).order_by(BorrowRecord.due_date)
    )
    
    borrow_records = result.scalars().all()
    
    # Get book details for each borrow record
    borrowed_books = []
    for record in borrow_records:
        # Get the book
        book_result = await session.execute(
            select(Book).where(Book.id == record.book_id)
        )
        book = book_result.scalar_one_or_none()
        
        if book:
            borrowed_books.append({
                "borrow_id": record.id,
                "book_id": book.id,
                "title": book.title,
                "author": book.author,
                "borrowed_date": record.borrowed_date,
                "due_date": record.due_date,
                "days_remaining": (record.due_date - datetime.utcnow()).days,
                "renewal_count": record.renewal_count,
                "max_renewals": record.max_renewals
            })
    
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "borrowed_books": borrowed_books,
        "count": len(borrowed_books)
    }


@app.post("/books/{book_id}/borrow")
async def borrow_book(
    book_id: str,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Borrow a book - NO relationship version"""
    
    # 1. Check user borrowing limit
    if current_user.current_books_borrowed >= current_user.max_books_allowed:
        raise HTTPException(status_code=400, detail="Borrowing limit reached")
    
    # 2. Get book
    result = await session.execute(select(Book).where(Book.id == book_id))
    book = result.scalar_one_or_none()
    
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    if book.available_copies < 1:
        raise HTTPException(status_code=400, detail="No copies available")
    
    # 3. Check if user already borrowed this book
    existing_borrow = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.user_id == current_user.id,
            BorrowRecord.book_id == book_id,
            BorrowRecord.status == "borrowed"
        )
    )
    
    if existing_borrow.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Already borrowed this book")
    
    # 4. Create borrow record
    from datetime import timedelta
    borrowed_date = datetime.utcnow()
    due_date = borrowed_date + timedelta(days=14)
    
    borrow_record = BorrowRecord(
        user_id=current_user.id,
        book_id=book_id,
        borrowed_date=borrowed_date,
        due_date=due_date,
        status="borrowed"
    )
    
    # 5. Update book availability
    book.available_copies -= 1
    if book.available_copies == 0:
        book.status = "borrowed"
    
    # 6. Update user's borrowed count
    current_user.current_books_borrowed += 1
    
    # 7. Save everything
    session.add(borrow_record)
    await session.commit()
    
    # 8. Return success
    return {
        "message": f"Successfully borrowed '{book.title}'",
        "borrow_id": borrow_record.id,
        "book_title": book.title,
        "borrowed_date": borrow_record.borrowed_date,
        "due_date": borrow_record.due_date,
        "user_books_borrowed": current_user.current_books_borrowed,
        "book_available_copies": book.available_copies
    }