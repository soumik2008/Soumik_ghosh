from datetime import datetime, date
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Date
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class KeyValue(Base):
    __tablename__ = "key_values"
    id = Column(Integer, primary_key=True)
    k = Column(String(100), unique=True, nullable=False)
    v = Column(Text, nullable=True)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    password_hash = Column(Text, nullable=False)
    role = Column(String(20), default="user")          # "user" | "owner"
    approved = Column(Boolean, default=False)
    expiry = Column(Date, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    bots = relationship("Bot", back_populates="owner", cascade="all, delete-orphan")
    sessions = relationship("TerminalSession", back_populates="user", cascade="all, delete-orphan")

    def is_expired(self) -> bool:
        if not self.expiry:
            return False
        try:
            today = date.today()
            return today > self.expiry
        except Exception:
            return False

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}', approved={self.approved})>"

class Bot(Base):
    __tablename__ = "bots"
    id = Column(Integer, primary_key=True)
    uid = Column(String(40), unique=True, nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    filepath = Column(Text, nullable=False)

    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    owner = relationship("User", back_populates="bots")

    status = Column(String(30), default="stopped")     # "running" | "stopped" | "pending" | "rejected" | "deleted"
    pid = Column(Integer, nullable=True)
    token = Column(Text, nullable=True)
    auto_restart = Column(Boolean, default=False)
    logpath = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Bot(id={self.id}, uid='{self.uid}', filename='{self.filename}', status='{self.status}')>"

class TerminalSession(Base):
    __tablename__ = "terminal_sessions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    user = relationship("User", back_populates="sessions")
    session_data = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<TerminalSession(id={self.id}, user_id={self.user_id}, created_at={self.created_at})>"