from fastapi import FastAPI, HTTPException, Depends, File, Form, UploadFile, status
from app.schemas import uploadBook, uploadResponse, updateBook, updateResponse, UserRegister, UserResponse, UserProfileResponse, AdminRegisterRequest, AdminRegisterResponse, BorrowRequest, BorrowResponse, ReturnResponse, AdminApproveReturn, AdminApproveBorrow, BorrowStatus
from app.db import Book, User, BorrowRecord, create_db_and_tables, get_async_session 
from sqlalchemy.ext.asyncio import AsyncSession
from contextlib import asynccontextmanager
from sqlalchemy import select, func

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


@app.post("/books/{book_id}/borrow", response_model=BorrowResponse)
async def request_borrow_book(
    book_id: str,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Request to borrow a book (creates pending approval request)"""
    
    # 1. Check user borrowing limit (including pending requests)
    # Count both borrowed and pending books
    borrow_count_result = await session.execute(
        select(func.count(BorrowRecord.id)).where(
            BorrowRecord.user_id == current_user.id,
            BorrowRecord.status.in_(["borrowed", "pending_approval"])
        )
    )
    total_borrow_count = borrow_count_result.scalar()
    
    if total_borrow_count >= current_user.max_books_allowed:
        raise HTTPException(
            status_code=400, 
            detail=f"Borrowing limit reached. You have {total_borrow_count} books (including pending requests)"
        )
    
    # 2. Get book
    result = await session.execute(select(Book).where(Book.id == book_id))
    book = result.scalar_one_or_none()
    
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    # Check available copies
    if book.available_copies < 1:
        raise HTTPException(status_code=400, detail="No copies available")
    
    # 3. Check if user already has a pending or active borrow for this book
    existing_borrow = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.user_id == current_user.id,
            BorrowRecord.book_id == book_id,
            BorrowRecord.status.in_(["borrowed", "pending_approval"])
        )
    )
    
    if existing_borrow.scalar_one_or_none():
        raise HTTPException(
            status_code=400, 
            detail="Already borrowed or pending approval for this book"
        )
    
    # 4. Create PENDING borrow record (NOT approved yet)
    borrow_record = BorrowRecord(
        user_id=current_user.id,
        book_id=book_id,
        status="pending_approval"  # Important: Not "borrowed" yet
        # due_date will be set when admin approves
        # book copies NOT reduced yet
        # user count NOT increased yet
    )
    
    session.add(borrow_record)
    await session.commit()
    
    # 5. Log the request (optional)
    print(f"Borrow request created: User {current_user.username} requested book '{book.title}'")
    
    return BorrowResponse(
        message=f"Borrow request submitted for '{book.title}'. Awaiting admin approval.",
        borrow_id=borrow_record.id,
        book_title=book.title,
        borrowed_date=borrow_record.borrowed_date,
        due_date=None,  # Not set until approved
        renewal_count=0,
        status=BorrowStatus.PENDING
    )

@app.post("/admin/borrows/approve", response_model=BorrowResponse)
async def admin_approve_borrow(
    approve_data: AdminApproveBorrow,
    current_user: User = Depends(get_current_admin_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Admin approves or rejects a borrow request"""
    
    # 1. Find the pending borrow record
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.id == approve_data.borrow_id,
            BorrowRecord.status == "pending_approval"
        )
    )
    
    borrow_record = result.scalar_one_or_none()
    
    if not borrow_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending borrow request not found"
        )
    
    # 2. Get the book
    book_result = await session.execute(
        select(Book).where(Book.id == borrow_record.book_id)
    )
    book = book_result.scalar_one_or_none()
    
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    # 3. Get the user who requested
    user_result = await session.execute(
        select(User).where(User.id == borrow_record.user_id)
    )
    user = user_result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    approval_date = datetime.utcnow()
    
    if approve_data.approve:
        # Check if book is still available
        if book.available_copies < 1:
            # Reject if no copies available
            borrow_record.status = "rejected"
            borrow_record.approval_notes = f"Rejected: No copies available when reviewing"
            borrow_record.approved_by = current_user.id
            borrow_record.approval_date = approval_date
            
            message = f"Request rejected: No copies of '{book.title}' available"
            status_str = BorrowStatus.REJECTED
        else:
            # APPROVE the request
            from datetime import timedelta
            
            # Set due date (default 14 days or custom)
            due_days = approve_data.due_date_days or 14
            due_date = approval_date + timedelta(days=due_days)
            
            borrow_record.status = "borrowed"
            borrow_record.due_date = due_date
            borrow_record.approved_by = current_user.id
            borrow_record.approval_notes = approve_data.notes
            borrow_record.approval_date = approval_date
            
            # Update book availability
            book.available_copies -= 1
            if book.available_copies == 0:
                book.status = "borrowed"
            
            # Update user's borrowed count
            user.current_books_borrowed += 1
            
            message = f"Borrow request approved for '{book.title}'. Due date: {due_date.strftime('%Y-%m-%d')}"
            status_str = BorrowStatus.APPROVED
            
            # Send notification (optional)
            print(f"Borrow approved: User {user.username} can collect '{book.title}'")
    else:
        # REJECT the request
        borrow_record.status = "rejected"
        borrow_record.approved_by = current_user.id
        borrow_record.approval_notes = approve_data.notes or "Rejected by admin"
        borrow_record.approval_date = approval_date
        
        message = f"Borrow request rejected for '{book.title}'"
        status_str = BorrowStatus.REJECTED
    
    # 4. Save changes
    await session.commit()
    
    return BorrowResponse(
        message=message,
        borrow_id=borrow_record.id,
        book_title=book.title,
        borrowed_date=borrow_record.borrowed_date,
        due_date=borrow_record.due_date,
        renewal_count=borrow_record.renewal_count,
        status=status_str
    )

@app.get("/admin/borrows/pending")
async def get_pending_borrows(
    current_user: User = Depends(get_current_admin_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Get all pending borrow requests (Admin only)"""
    
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.status == "pending_approval"
        ).order_by(BorrowRecord.borrowed_date)
    )
    
    pending_records = result.scalars().all()
    
    pending_borrows = []
    for record in pending_records:
        # Get book details
        book_result = await session.execute(
            select(Book).where(Book.id == record.book_id)
        )
        book = book_result.scalar_one_or_none()
        
        # Get user details
        user_result = await session.execute(
            select(User).where(User.id == record.user_id)
        )
        user = user_result.scalar_one_or_none()
        
        if book and user:
            days_pending = (datetime.utcnow() - record.borrowed_date).days
            
            pending_borrows.append({
                "borrow_id": record.id,
                "book_id": book.id,
                "book_title": book.title,
                "author": book.author,
                "isbn": book.isbn,
                "available_copies": book.available_copies,
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "current_books_borrowed": user.current_books_borrowed,
                "max_books_allowed": user.max_books_allowed,
                "borrowed_date": record.borrowed_date,
                "days_pending": days_pending,
                "approve_url": f"/admin/borrows/approve",
                "reject_url": f"/admin/borrows/approve"
            })
    
    return {
        "pending_count": len(pending_borrows),
        "checked_at": datetime.utcnow(),
        "pending_borrows": pending_borrows
    }

@app.get("/users/me/pending-borrows")
async def get_my_pending_borrows(
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Get current user's pending borrow requests"""
    
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.user_id == current_user.id,
            BorrowRecord.status == "pending_approval"
        ).order_by(BorrowRecord.borrowed_date)
    )
    
    pending_records = result.scalars().all()
    
    pending_borrows = []
    for record in pending_records:
        # Get book details
        book_result = await session.execute(
            select(Book).where(Book.id == record.book_id)
        )
        book = book_result.scalar_one_or_none()
        
        if book:
            days_pending = (datetime.utcnow() - record.borrowed_date).days
            
            pending_borrows.append({
                "borrow_id": record.id,
                "book_id": book.id,
                "book_title": book.title,
                "author": book.author,
                "borrowed_date": record.borrowed_date,
                "days_pending": days_pending,
                "status": record.status,
                "instructions": "Awaiting admin approval. You will be notified when approved."
            })
    
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "pending_borrows_count": len(pending_borrows),
        "pending_borrows": pending_borrows
    }


@app.post("/admin/borrow/{borrow_id}/return", response_model=ReturnResponse)
async def admin_return_book(
    borrow_id: str,
    current_user: User = Depends(get_current_admin_user),  # Admin only
    session: AsyncSession = Depends(get_async_session)
):
    """Admin return - can return any book (for librarians)"""
    
    # 1. Find the borrow record
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.id == borrow_id,
            BorrowRecord.status == "borrowed"
        )
    )
    
    borrow_record = result.scalar_one_or_none()
    
    if not borrow_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Borrow record not found or already returned"
        )
    
    # 2. Get the book
    book_result = await session.execute(
        select(Book).where(Book.id == borrow_record.book_id)
    )
    book = book_result.scalar_one_or_none()
    
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    # 3. Get the user who borrowed it
    user_result = await session.execute(
        select(User).where(User.id == borrow_record.user_id)
    )
    user = user_result.scalar_one_or_none()
    
    # 4. Update borrow record
    returned_date = datetime.utcnow()
    borrow_record.returned_date = returned_date
    borrow_record.status = "returned"
    
    # 5. Update book availability
    book.available_copies += 1
    if book.available_copies > 0 and book.status == "borrowed":
        book.status = "available"
    
    # 6. Update user's borrowed count (if user exists)
    if user:
        user.current_books_borrowed -= 1
    
    # 7. Save changes
    await session.commit()
    
    # 8. Log the admin return
    print(f"Admin {current_user.username} returned book '{book.title}' for user {borrow_record.user_id}")
    
    return ReturnResponse(
        message=f"Admin: Successfully returned '{book.title}'",
        borrow_id=borrow_record.id,
        book_title=book.title,
        book_id=book.id,
        user_id=borrow_record.user_id,
        borrowed_date=borrow_record.borrowed_date,
        returned_date=returned_date,
        user_books_borrowed=user.current_books_borrowed if user else 0,
        book_available_copies=book.available_copies
    )


@app.post("/borrow/{borrow_id}/return", response_model=ReturnResponse)
async def request_return_book(
    borrow_id: str,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_async_session)
):
    """User requests to return a book (creates pending return request)"""
    
    # 1. Find the borrow record - assuming you have a BorrowRecord SQLAlchemy model
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.id == borrow_id,
            BorrowRecord.user_id == current_user.id,
            BorrowRecord.status == "borrowed"
        )
    )
    
    borrow_record = result.scalar_one_or_none()
    
    if not borrow_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Borrow record not found, already returned, or you don't have permission"
        )
    
    # 2. Get the book
    book_result = await session.execute(
        select(Book).where(Book.id == borrow_record.book_id)
    )
    book = book_result.scalar_one_or_none()
    
    if not book:
        raise HTTPException(status_code=404, detail="Book not found in database")
    
    # 3. Update borrow record to pending return status
    return_requested_date = datetime.utcnow()
    borrow_record.return_requested_date = return_requested_date
    borrow_record.status = "pending_return"
    
    # Note: Book availability and user count NOT updated yet
    
    # 4. Save changes
    await session.commit()
    
    return ReturnResponse(
        message=f"Return request submitted for '{book.title}'. Please return the physical book to the library for approval.",
        borrow_id=borrow_record.id,
        book_title=book.title,
        book_id=book.id,
        user_id=current_user.id,
        borrowed_date=borrow_record.borrowed_date,
        returned_date=None,
        return_requested_date=return_requested_date,
        user_books_borrowed=current_user.current_books_borrowed,
        book_available_copies=book.available_copies,
        status="pending_return"
    )

@app.post("/admin/returns/approve", response_model=ReturnResponse)
async def admin_approve_return(
    approve_data: AdminApproveReturn,
    current_user: User = Depends(get_current_admin_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Admin approves or rejects a pending return request"""
    
    # 1. Find the borrow record with pending return status
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.id == approve_data.borrow_id,
            BorrowRecord.status == "pending_return"
        )
    )
    
    borrow_record = result.scalar_one_or_none()
    
    if not borrow_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Pending return request not found"
        )
    
    # 2. Get the book
    book_result = await session.execute(
        select(Book).where(Book.id == borrow_record.book_id)
    )
    book = book_result.scalar_one_or_none()
    
    if not book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    # 3. Get the user who borrowed it
    user_result = await session.execute(
        select(User).where(User.id == borrow_record.user_id)
    )
    user = user_result.scalar_one_or_none()
    
    if approve_data.approve:
        # 4. Update borrow record as returned
        returned_date = datetime.utcnow()
        borrow_record.returned_date = returned_date
        borrow_record.status = "returned"
        borrow_record.return_approved_by = current_user.id
        borrow_record.return_notes = approve_data.notes
        
        # 5. Update book availability
        book.available_copies += 1
        if book.available_copies > 0 and book.status == "borrowed":
            book.status = "available"
        
        # 6. Update user's borrowed count
        if user:
            user.current_books_borrowed -= 1
        
        message = f"Approved return of '{book.title}'"
        status_str = "returned"
    else:
        # Reject the return request - revert to borrowed status
        borrow_record.status = "borrowed"
        borrow_record.return_requested_date = None
        borrow_record.return_notes = f"Rejected: {approve_data.notes}" if approve_data.notes else "Rejected by admin"
        
        message = f"Rejected return request for '{book.title}'"
        status_str = "borrowed"
    
    # 7. Save changes
    await session.commit()
    
    return ReturnResponse(
        message=message,
        borrow_id=borrow_record.id,
        book_title=book.title,
        book_id=book.id,
        user_id=borrow_record.user_id,
        borrowed_date=borrow_record.borrowed_date,
        returned_date=borrow_record.returned_date if approve_data.approve else None,
        return_requested_date=borrow_record.return_requested_date,
        user_books_borrowed=user.current_books_borrowed if user else 0,
        book_available_copies=book.available_copies,
        status=status_str
    )

@app.get("/admin/returns/pending", response_model=dict)
async def get_pending_returns(
    current_user: User = Depends(get_current_admin_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Get all pending return requests (Admin only)"""
    
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.status == "pending_return"
        ).order_by(BorrowRecord.return_requested_date)
    )
    
    pending_records = result.scalars().all()
    
    pending_returns = []
    for record in pending_records:
        # Get book details
        book_result = await session.execute(
            select(Book).where(Book.id == record.book_id)
        )
        book = book_result.scalar_one_or_none()
        
        # Get user details
        user_result = await session.execute(
            select(User).where(User.id == record.user_id)
        )
        user = user_result.scalar_one_or_none()
        
        if book and user:
            days_pending = (datetime.utcnow() - record.return_requested_date).days if record.return_requested_date else 0
            days_borrowed = (datetime.utcnow() - record.borrowed_date).days
            
            pending_returns.append({
                "borrow_id": record.id,
                "book_id": book.id,
                "book_title": book.title,
                "author": book.author,
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "borrowed_date": record.borrowed_date,
                "due_date": record.due_date,
                "return_requested_date": record.return_requested_date,
                "days_pending": days_pending,
                "days_borrowed": days_borrowed,
                "renewal_count": record.renewal_count
            })
    
    return {
        "pending_count": len(pending_returns),
        "checked_at": datetime.utcnow(),
        "pending_returns": pending_returns
    }

@app.get("/users/me/pending-returns", response_model=dict)
async def get_my_pending_returns(
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Get current user's pending return requests"""
    
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.user_id == current_user.id,
            BorrowRecord.status == "pending_return"
        ).order_by(BorrowRecord.return_requested_date)
    )
    
    pending_records = result.scalars().all()
    
    pending_returns = []
    for record in pending_records:
        # Get book details
        book_result = await session.execute(
            select(Book).where(Book.id == record.book_id)
        )
        book = book_result.scalar_one_or_none()
        
        if book:
            days_pending = (datetime.utcnow() - record.return_requested_date).days if record.return_requested_date else 0
            
            pending_returns.append({
                "borrow_id": record.id,
                "book_id": book.id,
                "book_title": book.title,
                "author": book.author,
                "borrowed_date": record.borrowed_date,
                "return_requested_date": record.return_requested_date,
                "days_pending": days_pending,
                "status": "pending_return",
                "instructions": "Please bring the physical book to the library for approval"
            })
    
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "pending_returns_count": len(pending_returns),
        "pending_returns": pending_returns
    }

@app.get("/users/me/current-borrows")
async def get_my_current_borrows(
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Get current user's APPROVED borrowed books (not pending)"""
    
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.user_id == current_user.id,
            BorrowRecord.status == "borrowed"  # Only approved/borrowed books
        ).order_by(BorrowRecord.due_date)
    )
    
    borrow_records = result.scalars().all()
    
    current_borrows = []
    for record in borrow_records:
        # Get book details
        book_result = await session.execute(
            select(Book).where(Book.id == record.book_id)
        )
        book = book_result.scalar_one_or_none()
        
        if book:
            # Check if overdue
            is_overdue = datetime.utcnow() > record.due_date
            days_overdue = (datetime.utcnow() - record.due_date).days if is_overdue else 0
            
            current_borrows.append({
                "borrow_id": record.id,
                "book_id": book.id,
                "book_title": book.title,
                "author": book.author,
                "borrowed_date": record.borrowed_date,
                "due_date": record.due_date,
                "approved_by": record.approved_by,
                "approval_date": record.approval_date,
                "days_borrowed": (datetime.utcnow() - record.borrowed_date).days,
                "is_overdue": is_overdue,
                "days_overdue": days_overdue,
                "renewal_count": record.renewal_count,
                "max_renewals": record.max_renewals,
                "can_renew": record.renewal_count < record.max_renewals,
                "status": record.status
            })
    
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "current_borrows_count": len(current_borrows),
        "max_books_allowed": current_user.max_books_allowed,
        "available_slots": current_user.max_books_allowed - current_user.current_books_borrowed,
        "current_borrows": current_borrows
    }


@app.get("/users/me/all-borrow-requests")
async def get_my_all_borrow_requests(
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Get all borrow requests (pending, approved, rejected) for current user"""
    
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.user_id == current_user.id
        ).order_by(BorrowRecord.borrowed_date.desc())
    )
    
    all_records = result.scalars().all()
    
    all_requests = []
    for record in all_records:
        # Get book details
        book_result = await session.execute(
            select(Book).where(Book.id == record.book_id)
        )
        book = book_result.scalar_one_or_none()
        
        if book:
            request_info = {
                "borrow_id": record.id,
                "book_id": book.id,
                "book_title": book.title,
                "author": book.author,
                "status": record.status,
                "borrowed_date": record.borrowed_date,
                "due_date": record.due_date,
                "approved_by": record.approved_by,
                "approval_date": record.approval_date,
                "approval_notes": record.approval_notes,
                "returned_date": record.returned_date
            }
            
            # Add status-specific information
            if record.status == "pending_approval":
                request_info["message"] = "Awaiting admin approval"
                request_info["can_cancel"] = True
            elif record.status == "borrowed":
                request_info["message"] = "Approved - Book is with you"
                request_info["can_return"] = True
            elif record.status == "rejected":
                request_info["message"] = "Request was rejected"
                request_info["can_retry"] = True
            elif record.status == "returned":
                request_info["message"] = "Book returned"
            
            all_requests.append(request_info)
    
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "total_requests": len(all_requests),
        "requests": all_requests
    }



@app.delete("/borrow/{borrow_id}/cancel")
async def cancel_pending_borrow(
    borrow_id: str,
    current_user: User = Depends(get_current_active_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Cancel a pending borrow request"""
    
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.id == borrow_id,
            BorrowRecord.user_id == current_user.id,
            BorrowRecord.status == "pending_approval"
        )
    )
    
    borrow_record = result.scalar_one_or_none()
    
    if not borrow_record:
        raise HTTPException(
            status_code=404,
            detail="Pending borrow request not found or cannot be canceled"
        )
    
    # Delete the pending request
    await session.delete(borrow_record)
    await session.commit()
    
    return {
        "message": "Borrow request canceled successfully",
        "borrow_id": borrow_id
    }


@app.get("/admin/overdue-books")
async def get_overdue_books(
    current_user: User = Depends(get_current_admin_user),
    session: AsyncSession = Depends(get_async_session)
):
    """Get all overdue books (Admin only) - Include pending returns"""
    
    result = await session.execute(
        select(BorrowRecord).where(
            BorrowRecord.status.in_(["borrowed", "pending_return"]),
            BorrowRecord.due_date < datetime.utcnow()
        ).order_by(BorrowRecord.due_date)
    )
    
    overdue_records = result.scalars().all()
    
    overdue_books = []
    for record in overdue_records:
        # Get book details
        book_result = await session.execute(
            select(Book).where(Book.id == record.book_id)
        )
        book = book_result.scalar_one_or_none()
        
        # Get user details
        user_result = await session.execute(
            select(User).where(User.id == record.user_id)
        )
        user = user_result.scalar_one_or_none()
        
        if book and user:
            days_overdue = (datetime.utcnow() - record.due_date).days
            
            overdue_books.append({
                "borrow_id": record.id,
                "book_id": book.id,
                "book_title": book.title,
                "author": book.author,
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "borrowed_date": record.borrowed_date,
                "due_date": record.due_date,
                "days_overdue": days_overdue,
                "renewal_count": record.renewal_count,
                "status": record.status,
                "return_requested_date": record.return_requested_date if record.status == "pending_return" else None,
                "admin_action_url": f"/admin/returns/approve"
            })
    
    return {
        "overdue_count": len(overdue_books),
        "checked_at": datetime.utcnow(),
        "overdue_books": overdue_books
    }