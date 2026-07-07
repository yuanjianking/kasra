"""User behavior ORM model — daily activity summary for anomaly detection."""

from __future__ import annotations

from datetime import date, time

from sqlalchemy import Column, Date, Integer, String, Time, JSON

from app.database import Base


class UserBehavior(Base):
    """User behavior table — daily activity summary.

    Corresponds to the product spec §6.3 user_behavior table.
    Used for B-series behavior anomaly detection rules.
    """

    __tablename__ = "user_behavior"

    user_id = Column(String(128), primary_key=True)
    date = Column(Date, primary_key=True)

    # Request counts
    total_requests = Column(Integer, default=0, nullable=False)
    blocked_requests = Column(Integer, default=0, nullable=False)
    warned_requests = Column(Integer, default=0, nullable=False)

    # Timing
    first_request = Column(Time, nullable=True)
    last_request = Column(Time, nullable=True)

    # Rule trigger frequency: {"I-01": 3, "SEC-06": 1}
    rule_triggers = Column(JSON, nullable=True, default=dict)

    # Behavior scores
    anomaly_score = Column(Integer, default=0)  # 0-100
    ai_adoption_rate = Column(Integer, nullable=True)  # 0-100 percentage

    def __repr__(self) -> str:
        return (
            f"<UserBehavior(user={self.user_id}, date={self.date}, "
            f"reqs={self.total_requests}, blocks={self.blocked_requests})>"
        )
