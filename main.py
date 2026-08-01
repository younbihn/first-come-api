from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr, Field
import bcrypt

app = FastAPI()

@app.get("/")
def root():
    return {"status": "alive"}

@app.get("/hello")
def hello(name: str = "익명"):
    return {"message": f"안녕하세요, {name}님"}

class Item(BaseModel):
    name: str
    price: int

@app.post("/items")
def create_item(item: Item):
    return {"created": item.name, "price": item.price}

users_db: dict[str, dict] = {}   # 인메모리 저장소 (8월에 PostgreSQL로 교체)

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

class SignupRequest(BaseModel):
    email: EmailStr                      # 이메일 형식 자동 검증
    password: str = Field(min_length=8)  # 8자 미만이면 422

@app.post("/signup", status_code=201)
def signup(req: SignupRequest):
    if req.email in users_db:
        raise HTTPException(status_code=409, detail="이미 가입된 이메일입니다")
    users_db[req.email] = {
        "email": req.email,
        "hashed_password": hash_password(req.password),
    }
    return {"email": req.email, "message": "가입 완료"}