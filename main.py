from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import jwt
import datetime

secret_key = "eyeq_tech"
algorithm = "HS256"

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
users_db = {"admin": {"username": "admin", "password": pwd_context.hash("secret")}}

oath2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def authenticate_user(username: str, password: str):
    user = users_db.get(username)
    if not user or not pwd_context.verify(password, user["password"]):
        return False
    return user


def create_jwt_token(data: dict, expires_delta: int = 30):
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_delta)
    data["exp"] = expire
    return jwt.encode(data, secret_key, algorithm=algorithm)


# login
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    token = create_jwt_token({"sub": form_data.username})
    return {"token": token}


@app.get("/data")
def get_data(token):
    try:
        payload = jwt.decode(token, secret_key, algorithms=algorithm)
        username: str = payload.get("sub")
        if username not in users_db:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    return ("message": "Secure data")

