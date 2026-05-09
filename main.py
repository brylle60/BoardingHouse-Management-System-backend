from contextlib import asynccontextmanager
from fastapi import FastAPI

from config.database_config import init_database
from config.security_config import configure_cors
from config.jwt_middleware import JwtAuthMiddleware
from controllers.auth_controller import router as auth_router
from controllers.room_controller import router as room_router
from controllers.tenant_controller import router as tenant_router
from controllers.lease_controller import router as lease_router
from controllers.communication_controller import router as communication_router
from controllers.admin_controller import router as admin_router
from controllers.manager_controller import router as manager_router
from controllers.manager_role_request_controller import router as manager_request_router
from controllers.booking_request_controller import router as booking_router
from services.lease_expiry_scheduler import start_scheduler, stop_scheduler
from controllers.maintenance_request_controller import router as maintenance_router
from controllers.notification_controller import router as notification_route
from controllers.payment_controller import router as payment_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_database()
    start_scheduler()
    yield
    stop_scheduler()


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
app.include_router(tenant_router)
app.include_router(lease_router)
app.include_router(communication_router)
app.include_router(manager_router)
app.include_router(admin_router)
app.include_router(manager_request_router)
app.include_router(booking_router)
app.include_router(maintenance_router)
app.include_router(notification_route)
app.include_router(payment_router)

from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Boarding House Management System",
        version="1.0.0",
        routes=app.routes,
    )
    # Define the Security Scheme
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    # Requirement: Apply to all routes
    openapi_schema["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)