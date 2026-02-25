import os
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import jwt
from dotenv import load_dotenv


# Load env
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET")

print("Starting server...")

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= ENV VARIABLES =================
MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET")

if not MONGO_URI or not JWT_SECRET:
    raise Exception("❌ Missing MONGO_URI or JWT_SECRET")

# ================= DATABASE =================
client = AsyncIOMotorClient(MONGO_URI)
db = client["auth_database"]
users_collection = db["users"]

print("✅ MongoDB Atlas Connected!")

# ================= PASSWORD HASHING =================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# ================= JWT =================
def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=1)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm="HS256")

# ================= SCHEMAS =================
class RegisterModel(BaseModel):
    name: str
    email: EmailStr
    phone: str
    password: str
    confirmPassword: str
    role: str

class LoginModel(BaseModel):
    email: EmailStr
    password: str
    role: str

# ================= REGISTER =================
@app.post("/register")
async def register(user: RegisterModel):

    # 1️⃣ Check all fields
    if not all([user.name, user.email, user.phone, user.password, user.confirmPassword, user.role]):
        raise HTTPException(status_code=400, detail="All fields are required")

    # 2️⃣ Check password match
    if user.password != user.confirmPassword:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    # 3️⃣ Check role validity
    if user.role not in ["student", "driver"]:
        raise HTTPException(status_code=400, detail="Invalid role selected")

    # 4️⃣ Check if email exists
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")

    # 5️⃣ Hash password
    hashed_password = hash_password(user.password)

    # 6️⃣ Create user
    new_user = {
        "name": user.name,
        "email": user.email,
        "phone": user.phone,
        "password": hashed_password,
        "role": user.role,
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow()
    }

    await users_collection.insert_one(new_user)

    return {"message": "Account created successfully!"}


# ================= LOGIN =================
@app.post("/login")
async def login(data: LoginModel):

    # 1️⃣ Check required fields
    if not data.email or not data.password or not data.role:
        raise HTTPException(status_code=400, detail="Email, password and role are required")

    # 2️⃣ Check if email exists
    user = await users_collection.find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    # 3️⃣ Check role
    if user["role"] != data.role:
        raise HTTPException(status_code=400, detail="Incorrect role selected")

    # 4️⃣ Verify password
    if not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    # 5️⃣ Generate token
    token = create_token({
        "id": str(user["_id"]),
        "role": user["role"]
    })

    return {
        "message": "Login successful!",
        "token": token,
        "role": user["role"],
        "user": {
            "name": user["name"],
            "email": user["email"],
            "phone": user["phone"]
        }
    }


# ================= ROOT =================
@app.get("/")
def root():
    return {"message": "Authentication Backend Running 🚀"}