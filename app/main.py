from fastapi import FastAPI
from .db import Base, engine
from .routes import auth as auth_routes
from .routes import users as users_routes

Base.metadata.create_all(bind=engine)

app = FastAPI(title="jwt-secure-auth - week2")

app.include_router(auth_routes.router)
app.include_router(users_routes.router)

@app.get("/")
def root():
    return {"msg": "jwt-secure-auth (week2) running"}
