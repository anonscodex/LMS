from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
from typing import Optional
from datetime import datetime
from enum import Enum



@field_validator('confirm_password')
@classmethod
def passwords_match(cls, v: str, info) -> str:
        """Check that passwords match"""
        if 'password' in info.data and v != info.data['password']:
            raise ValueError('Passwords do not match')
        return v
    
@field_validator('password')
@classmethod
def password_strength(cls, v: str) -> str:
        """Check password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

class uploadBook(BaseModel):
    
    url: str
    title: str
    description: str
    author: str
    isbn: str
    publisher: str
    publication_year: str
    category: str
    total_copies: str
    available_copies: str
    status: str

class uploadResponse(BaseModel):
    id: str
    url: Optional[str] = None  # Make optional and nullable
    title: str
    description: str
    author: str
    isbn: Optional[str] = None  # Make optional
    publisher: Optional[str] = None  # Make optional
    publication_year: Optional[int] = None  # Should be int, not str
    category: Optional[str] = None  # Make optional
    total_copies: int  # Should be int, not str
    available_copies: int  # Should be int, not str
    status: str


class updateBook(BaseModel):
    total_copies: Optional[int] = None
    available_copies: Optional[int] = None
    status: Optional[str] = None
    
    @field_validator('status')
    @classmethod
    def validate_status(cls, v: Optional[str]) -> Optional[str]:
        if v and v not in ["available", "borrowed", "reserved", "maintenance", "lost"]:
            raise ValueError('Status must be: available, borrowed, reserved, maintenance, or lost')
        return v
    
    @field_validator('available_copies')
    @classmethod
    def validate_available_copies(cls, v: Optional[int], info) -> Optional[int]:
        if v is not None and v < 0:
            raise ValueError('Available copies cannot be negative')
        
        # Check if available_copies exceeds total_copies
        if 'total_copies' in info.data and info.data['total_copies'] is not None:
            if v > info.data['total_copies']:
                raise ValueError('Available copies cannot exceed total copies')
        
        return v

class updateResponse(BaseModel):
    message: str
    book: uploadResponse  # Reuse your existing uploadResponse model
    
    model_config = ConfigDict(from_attributes=True)



class UserRegister(BaseModel):
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    password: str
    confirm_password: str
    student_id: Optional[str] = None

# Admin registration request model
class AdminRegisterRequest(BaseModel):
    email: EmailStr
    username: str
    full_name: str
    password: str
    confirm_password: str
    secret_key: str
    
    @field_validator('password')
    @classmethod
    def validate_password_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v
    
    @field_validator('confirm_password')
    @classmethod
    def validate_passwords_match(cls, v: str, info) -> str:
        if 'password' in info.data and v != info.data['password']:
            raise ValueError('Passwords do not match')
        return v
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str) -> str:
        if len(v) < 3:
            raise ValueError('Username must be at least 3 characters')
        if ' ' in v:
            raise ValueError('Username cannot contain spaces')
        return v

# Admin registration response model
class AdminRegisterResponse(BaseModel):
    message: str
    user_id: str
    email: str
    username: str
    is_admin: bool
    created_at: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)
    


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str] = None
    student_id: Optional[str] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)




class LoginRequest(BaseModel):
    username_or_email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class TokenData(BaseModel):
    user_id: Optional[str] = None
    username: Optional[str] = None

class UserLoginResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str]
    student_id: Optional[str]
    is_admin: bool
    max_books_allowed: Optional[int] = None  # Make it optional
    access_token: str
    token_type: str = "bearer"
    
    model_config = ConfigDict(from_attributes=True)


class UserProfileResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str] = None
    student_id: Optional[str] = None
    is_admin: bool
    max_books_allowed: Optional[int] = 5
    current_books_borrowed: Optional[int] = 0
    total_books_borrowed: Optional[int] = 0
    created_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


class BorrowRequest(BaseModel):
    book_id: str
    borrow_days: Optional[int] = 14  # Default 2 weeks
    
    @field_validator('borrow_days')
    @classmethod
    def validate_borrow_days(cls, v: int) -> int:
        if v < 1:
            raise ValueError('Borrow days must be at least 1')
        if v > 90:  # Maximum 3 months
            raise ValueError('Borrow days cannot exceed 90 days')
        return v

class BorrowResponse(BaseModel):
    message: str
    borrow_id: str
    book_title: str
    borrowed_date: datetime
    due_date: Optional[datetime] = None 
    renewal_count: int
    status: str
    
    model_config = ConfigDict(from_attributes=True)

class ReturnRequest(BaseModel):
    """Request model for returning a book"""
    borrow_id: str

class ReturnResponse(BaseModel):
    """Response model for returning a book"""
    message: str
    borrow_id: str
    book_title: str
    book_id: str
    user_id: str
    borrowed_date: datetime
    returned_date: Optional[datetime] = None 
    user_books_borrowed: int
    book_available_copies: int
    
    model_config = ConfigDict(from_attributes=True)

class ReturnStatus(str, Enum):
    PENDING = "pending_return"
    APPROVED = "returned"
    BORROWED = "borrowed"


class AdminApproveReturn(BaseModel):
    """Admin approve return request"""
    borrow_id: str
    approve: bool = True
    notes: Optional[str] = None

class PendingReturnResponse(BaseModel):
    """Response for pending returns"""
    borrow_id: str
    book_id: str
    book_title: str
    author: str
    user_id: str
    username: str
    email: str
    borrowed_date: datetime
    due_date: datetime
    return_requested_date: datetime
    days_pending: int
    days_borrowed: int
    renewal_count: int

class UserPendingReturn(BaseModel):
    """User's pending returns"""
    borrow_id: str
    book_id: str
    book_title: str
    author: str
    borrowed_date: datetime
    return_requested_date: datetime
    days_pending: int
    status: str
    instructions: str

class BorrowStatus(str, Enum):
    PENDING = "pending_approval"
    APPROVED = "borrowed"
    REJECTED = "rejected"
    RETURNED = "returned"

class AdminApproveBorrow(BaseModel):
    """Admin approve/reject borrow request"""
    borrow_id: str
    approve: bool = True
    notes: Optional[str] = None
    due_date_days: Optional[int] = 14  # Default 14 days