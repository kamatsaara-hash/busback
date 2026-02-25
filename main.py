import os
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import jwt
from dotenv import load_dotenv

# ================= LOAD ENV =================
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET")

if not MONGO_URI or not JWT_SECRET:
    raise Exception("❌ Missing MONGO_URI or JWT_SECRET")

print("🚀 Starting FastAPI Server...")

# ================= APP =================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change to frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= DATABASE =================
client = AsyncIOMotorClient(MONGO_URI)
db = client["auth_database"]
users_collection = db["users"]

print("✅ Connected to MongoDB Atlas")

# ================= PASSWORD HASHING =================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

# ================= JWT =================
def create_token(user_id: str, role: str):
    payload = {
        "id": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(days=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

# ================= MODELS =================
class RegisterModel(BaseModel):
    name: str
    email: EmailStr
    phone: str
    password: str
    confirmPassword: str

class LoginModel(BaseModel):
    email: EmailStr
    password: str

# ================= REGISTER =================
@app.post("/register")
async def register(user: RegisterModel):

    # Password match check
    if user.password != user.confirmPassword:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # Check if email exists
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")

    # Hash password
    hashed_password = hash_password(user.password)

    # Create user (default role = student)
    new_user = {
        "name": user.name,
        "email": user.email,
        "phone": user.phone,
        "password": hashed_password,
        "role": "student",
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow(),
        "lastLogin": None
    }

    await users_collection.insert_one(new_user)

    return {
        "message": "Account created successfully!",
        "redirect": "/login"
    }

# ================= LOGIN =================
@app.post("/login")
async def login(data: LoginModel):

    # Check if user exists
    user = await users_collection.find_one({"email": data.email})

    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    # Verify password
    if not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    # Update last login
    await users_collection.update_one(
        {"email": data.email},
        {"$set": {"lastLogin": datetime.utcnow()}}
    )

    # Generate token
    token = create_token(str(user["_id"]), user["role"])

    return {
        "message": "Login successful!",
        "token": token,
        "role": user["role"],
        "redirect": "/main"
    }

# ================= ROOT =================
@app.get("/")
async def root():
    return {"message": "Authentication Backend Running 🚀"}