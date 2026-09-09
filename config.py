import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///aegis.db")
