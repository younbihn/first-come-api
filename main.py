from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr, Field
import bcrypt
import logging
from fastapi import FastAPI, HTTPException, Request

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

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

def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked = local[0] + "*"
    else:
        masked = local[:2] + "*" * (len(local) - 2)
    return f"{masked}@{domain}"

def mask_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:                      # IPv4: 마지막 옥텟 가림
        return ".".join(parts[:3] + ["*"])
    return ip.rsplit(":", 1)[0] + ":*"       # IPv6 대략 처리

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

class SignupRequest(BaseModel):
    email: EmailStr                      # 이메일 형식 자동 검증
    password: str = Field(min_length=8)  # 8자 미만이면 422

@app.post("/signup", status_code=201)
def signup(req: SignupRequest, request: Request):
    if req.email in users_db:
        raise HTTPException(status_code=409, detail="이미 가입된 이메일입니다")
    users_db[req.email] = {
        "email": req.email,
        "hashed_password": hash_password(req.password),
    }
    client_ip = request.client.host if request.client else "unknown"
    logger.info(
        "signup completed: email=%s ip=%s",
        mask_email(req.email),
        mask_ip(client_ip),
    )
    return {"email": req.email, "message": "가입 완료"}