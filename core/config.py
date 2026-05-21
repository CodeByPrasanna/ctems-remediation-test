from dotenv import load_dotenv
import os

# Load variables from .env
load_dotenv()


# Database
DATABASE_URL = os.getenv(
    "DATABASE_URL"
)


# GitHub Token
GITHUB_TOKEN = os.getenv(
    "GITHUB_TOKEN"
)


# Gemini API
GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY"
)