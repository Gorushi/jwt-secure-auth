from fastapi import FastAPI
from . import models
from .db import engine
from .routes import auth, users

# DB 테이블 생성
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# 라우터 포함
app.include_router(auth.router)
app.include_router(users.router)

@app.get("/")
def read_root():
    return {"Hello": "World"}
