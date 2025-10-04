from fastapi import FastAPI
from .db import Base, engine
from .routes import auth as auth_routes

# DB 테이블 생성 (개발용)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="jwt-secure-auth - week1")

app.include_router(auth_routes.router)

@app.get("/")
def root():
    return {"msg": "jwt-secure-auth (week1) running"}

