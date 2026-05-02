from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

client = MongoClient(os.getenv("DATABASE_URL"))
db = client[os.getenv("MONGODB_NAME")]  # "brylle"

#Match your exact Atlas collection names
users_col     = db["user"]      
otp_col       = db["otp_codes"]  
rooms_col     = db["rooms"]       
tenants_col   = db["tenants"]     

# 🆕 Still needs to be created in Atlas
payments_col  = db["payments"]
landlords_col = db["landlords"]

def test_connection():
    try:
        client.admin.command("ping")
        print(f"Connected to MongoDB — DB: '{db.name}'")
    except Exception as e:
        print(f"Connection failed: {e}")