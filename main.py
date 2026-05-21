from core.database import engine
from core.database import Base

from models.pr_models import PullRequest

Base.metadata.create_all(
    bind=engine
)

print("Database Created")