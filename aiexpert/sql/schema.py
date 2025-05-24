from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import mapped_column
from sqlalchemy import BigInteger, Boolean, func, DateTime, UniqueConstraint, String,Integer, LargeBinary, ForeignKey

from sqlalchemy.orm import Mapped

from datetime import datetime


from .connection import get_async_db_engine

class Base(DeclarativeBase):
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class ConversationSummary(Base):
    __tablename__ = 'conversation_summary'
    
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str] = mapped_column(String(200))
    assistant_id: Mapped[int] = mapped_column(Integer, ForeignKey('assistants.id'))
    title: Mapped[str] = mapped_column(String(100))
    num_of_messages: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now()) 
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now()) 
    status: Mapped[str] = mapped_column(String(10))
    thread_id: Mapped[str] = mapped_column(String(50))
    favorite: Mapped[bool] = mapped_column(Boolean, default=False)

class Assistants(Base):
    __tablename__ = 'assistants'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assistant_name: Mapped[str] = mapped_column(String(50), unique=True) 
    description: Mapped[str] = mapped_column(String(1000))
    endpoint: Mapped[str] = mapped_column(String(1000))
    assistant_code: Mapped[str] = mapped_column(String(100), unique=True)
    
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns if column.name != 'assistant_code'}

# Assistant Permissions table
class AssistantPermissions(Base):
    __tablename__ = 'assistant_permissions'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assistant_id: Mapped[int] = mapped_column(Integer, ForeignKey('assistants.id'))  
    group_id: Mapped[str] = mapped_column(String(50), ForeignKey('organization_groups.group_id'))

    
    __table_args__ = (
        UniqueConstraint('assistant_id', 'group_id', name='uix_assistant_group'),
    )


class AuthenTokens(Base):
    __tablename__ = 'authen_tokens'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_key: Mapped[str] = mapped_column(String(200))
    encrypted_tokens: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now()) 
    refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True) 

    __table_args__ = (
        UniqueConstraint('session_key', name='uix_session_key'),
    )
    
class OrganizationGroups(Base):
    __tablename__ = 'organization_groups'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[str] = mapped_column(String(50), unique=True)
    group_name: Mapped[str] = mapped_column(String(200), unique=True)
    group_title: Mapped[str] = mapped_column(String(200))
    group_description: Mapped[str] = mapped_column(String(200))
    assistant_group_name: Mapped[str] = mapped_column(String(100))
    role_name: Mapped[str] = mapped_column(String(50))
    created_by: Mapped[str] = mapped_column(String(200))
    updated_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now()) 
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now())
    
class GroupUsers(Base):
    __tablename__ = 'group_users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[str] = mapped_column(String(50), ForeignKey('organization_groups.group_id'))
    email: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(50), default='PENDING')
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now()) 
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=func.now()) 

class Users(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    diam_user_id: Mapped[str] = mapped_column(String(50), unique=True)
    email: Mapped[str] = mapped_column(String(200), unique=True)
    
async def init():
    engine = get_async_db_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    