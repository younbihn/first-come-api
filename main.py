from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
import bcrypt
import jwt
import logging

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

SECRET_KEY = "dev-secret-change-me"   # 실제 서비스면 환경변수로 (아래 설명 참고)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

def create_access_token(email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": email,                                              # 토큰 주인
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),  # 만료 시각
        "iat": now,                                                # 발급 시각
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/login")
def login(req: LoginRequest, request: Request):
    user = users_db.get(req.email)
    if not user or not verify_password(req.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 올바르지 않습니다")
    client_ip = request.client.host if request.client else "unknown"
    logger.info("login success: email=%s ip=%s", mask_email(req.email), mask_ip(client_ip))
    return {"access_token": create_access_token(req.email), "token_type": "bearer"}

security = HTTPBearer()

def get_current_user(cred: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        payload = jwt.decode(cred.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다")

    user = users_db.get(payload.get("sub"))
    if not user:
        raise HTTPException(status_code=401, detail="존재하지 않는 사용자입니다")
    return user

@app.get("/me")
def me(user: dict = Depends(get_current_user)):
    return {"email": user["email"]}