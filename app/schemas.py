from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
from typing import Optional
from datetime import datetime



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
    id: str  # Make sure this is included
    url: str  # Add this field
    title: str
    description: str
    author: str
    isbn: str
    publisher: str
    publication_year: str
    category: str
    total_copies: str
    available_copies: str
    status: str  # "available", "borrowed", "reserved", etc.

class updateBook(BaseModel):
    status: str

class updateResponse(BaseModel):
    message: str
    book: dict



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