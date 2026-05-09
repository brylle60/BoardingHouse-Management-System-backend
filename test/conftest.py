import pytest
from httpx import ASGITransport, AsyncClient
from config.jwt_config import jwt_config
from main import app
from config.database_config import init_database  # Import your function from where it lives
from models.user import RoleName, User, UserStatus
from passlib.context import CryptContext

# Use the public generate_token method
TEST_TOKEN = jwt_config.generate_token(
    username="64f1000000000000000000a1",  # This populates the "sub" claim
    extra_claims={
        "username": "test_admin",
        "roles": ["ROLE_ADMIN"],  # Changed from "role" to "roles" (as a list)
    }
)
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_TOKEN}"}
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@pytest.fixture(autouse=True)
async def db_init():
    """
    Initializes the database. 
    By removing scope="session", it defaults to "function" scope.
    """
    await init_database()

@pytest.fixture(autouse=True)
async def setup_test_user(db_init):
    # await User.find_all().delete()

    test_user = User(
        # Ensure this username matches what is inside your TEST_TOKEN
        username="64f1000000000000000000a1", 
        email="admin@test.com",
        password=pwd_context.hash("testpassword"),
        # CHANGE THIS: Use the string "ROLE_ADMIN" to match your RoleChecker
        role="ROLE_ADMIN", 
        status=UserStatus.ACTIVE
    )
    await test_user.insert()
@pytest.fixture
async def client(db_init): # <--- Also ensure client waits for DB
    async with AsyncClient(
        transport=ASGITransport(app=app), 
        base_url="http://test",
        headers=AUTH_HEADERS 
    ) as ac:
        yield ac