from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL=os.getenv(
    "DATABASE_URL"
)

GITHUB_TOKEN=os.getenv(
    "GITHUB_TOKEN"
)

GEMINI_API_KEY=os.getenv(
    "GEMINI_API_KEY"
)