from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import DateTime
from sqlalchemy.sql import func

from core.database import Base


class PullRequest(Base):

    __tablename__ = "pull_requests"

    id = Column(Integer, primary_key=True)

    repo_name = Column(String)

    branch_name = Column(String)

    pr_url = Column(String)

    pr_status = Column(String)

    removed_scopes = Column(String)

    added_scopes = Column(String)

    developer_name = Column(String)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    merged_at = Column(
        DateTime(timezone=True),
        nullable=True
    )