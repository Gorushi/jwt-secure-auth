from pydantic import BaseModel, constr

class Signup(BaseModel):
    username: str
    password: constr(min_length=8, max_length=64)  # bcrypt 안전 범위 내로 제한

class Login(BaseModel):
    username: str
    password: str

