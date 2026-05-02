from contextlib import asynccontextmanager
from fastapi import FastAPI

from config.database_config import init_database
from config.security_config import configure_cors
from config.jwt_middleware import JwtAuthMiddleware
from controllers.auth_controller import router as auth_router
from controllers.room_controller import router as room_router   
from controllers.admin_controller import router as admin_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_database()
    yield

app = FastAPI(
    title="Boarding House Management System",
    description="Python/FastAPI port of the Spring Boot auth layer",
    version="1.0.0",
    lifespan=lifespan,
)

configure_cors(app)
app.add_middleware(JwtAuthMiddleware)

app.include_router(room_router)   
app.include_router(auth_router)
app.include_router(admin_router)

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)