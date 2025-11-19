"""
Database Schemas for Cybersecurity Awareness Game

Each Pydantic model represents a collection in MongoDB.
Collection name = lowercase of class name.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any


class User(BaseModel):
    """Users collection schema -> collection: "user"""
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="User email (unique)")
    password_hash: str = Field(..., description="Password hash (server-side only)")
    token: Optional[str] = Field(None, description="Session token for simple auth")


class Question(BaseModel):
    """Questions for quizzes -> collection: "question"""
    category: str = Field(..., description="Module category, e.g., phishing, credential, rogueapps")
    prompt: str = Field(..., description="Question text or scenario")
    options: List[str] = Field(..., min_length=2, description="Multiple choice options")
    correct_index: int = Field(..., ge=0, description="Index of correct option in options list")
    explanation: Optional[str] = Field(None, description="Explanation shown after answering")
    difficulty: Optional[str] = Field("easy", description="Difficulty level: easy/medium/hard")


class Attempt(BaseModel):
    """Quiz attempts -> collection: "attempt"""
    user_id: str = Field(..., description="Reference to user _id as string")
    category: str = Field(..., description="Which module the attempt belongs to")
    answers: List[int] = Field(..., description="Selected option index for each question in order")
    correct_count: int = Field(..., ge=0, description="Number of correct answers")
    total: int = Field(..., ge=1, description="Total number of questions in the attempt")
    score: float = Field(..., ge=0, le=100, description="Score percentage 0-100")


class Progress(BaseModel):
    """Aggregated progress per user -> collection: "progress"""
    user_id: str = Field(...)
    by_category: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Per-category stats: attempts, best_score, last_score"
    )
