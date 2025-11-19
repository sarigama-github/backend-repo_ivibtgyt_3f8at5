import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict, Any
from bson import ObjectId
from datetime import datetime
from hashlib import sha256

from database import db, create_document, get_documents
from schemas import User, Question, Attempt, Progress

app = FastAPI(title="Cybersecurity Awareness Game API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Cybersecurity Awareness Game API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
                response["connection_status"] = "Connected"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:80]}"
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"

    return response


# --------- Auth (simple session token) ---------
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


def hash_password(password: str) -> str:
    return sha256(password.encode()).hexdigest()


@app.post("/auth/register")
def register(body: RegisterRequest):
    # Ensure email uniqueness
    existing = db["user"].find_one({"email": body.email}) if db else None
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(name=body.name, email=body.email, password_hash=hash_password(body.password))
    user_id = create_document("user", user)

    return {"user_id": user_id, "message": "Registered successfully"}


@app.post("/auth/login")
def login(body: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    user = db["user"].find_one({"email": body.email, "password_hash": hash_password(body.password)})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = sha256(f"{user['_id']}{datetime.utcnow()}".encode()).hexdigest()
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"token": token}})
    return {"token": token, "user": {"id": str(user["_id"]), "name": user["name"], "email": user["email"]}}


def get_user_by_token(token: str) -> Optional[dict]:
    if not token or db is None:
        return None
    return db["user"].find_one({"token": token})


# --------- Questions & Content ---------
class QuestionCreate(BaseModel):
    category: str
    prompt: str
    options: List[str]
    correct_index: int
    explanation: Optional[str] = None
    difficulty: Optional[str] = "easy"


@app.post("/content/question")
def create_question(body: QuestionCreate):
    q = Question(**body.model_dump())
    q_id = create_document("question", q)
    return {"id": q_id}


@app.get("/content/questions")
def list_questions(category: Optional[str] = None, limit: int = 20):
    filt = {"category": category} if category else {}
    items = get_documents("question", filt, limit)
    # Serialize ObjectId
    for it in items:
        it["id"] = str(it.pop("_id"))
    return items


# Seed a minimal set of sample questions (idempotent)
@app.post("/content/seed")
def seed_questions():
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    count = db["question"].count_documents({})
    if count > 0:
        return {"message": "Questions already seeded", "count": count}

    samples = [
        {
            "category": "phishing",
            "prompt": "You receive an email from 'IT Support' asking to reset your password via a link. The sender address looks odd. What should you do?",
            "options": [
                "Click the link and reset immediately",
                "Ignore the email or verify via official IT channel",
                "Forward to friends to warn them",
                "Reply asking for more details"
            ],
            "correct_index": 1,
            "explanation": "Always verify using official channels. Suspicious links could be phishing.",
            "difficulty": "easy"
        },
        {
            "category": "credential",
            "prompt": "You signed up for a new app. To save time, you reuse your school account password. Is this safe?",
            "options": ["Yes, if the app is popular", "No, use a unique password for each account", "Only if you enable dark mode", "Yes, if you use incognito"],
            "correct_index": 1,
            "explanation": "Credential reuse increases risk. Use unique passwords or a password manager.",
            "difficulty": "easy"
        },
        {
            "category": "rogueapps",
            "prompt": "A game APK from an unknown website promises free coins. What is the safest action?",
            "options": [
                "Install it and see",
                "Scan it with random tools",
                "Download but don't install",
                "Avoid and only install from official stores"
            ],
            "correct_index": 3,
            "explanation": "Rogue apps often carry malware. Use official app stores only.",
            "difficulty": "easy"
        }
    ]

    for s in samples:
        db["question"].insert_one({**s, "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()})

    return {"message": "Seeded", "count": len(samples)}


# --------- Attempts & Progress ---------
class SubmitAttemptRequest(BaseModel):
    token: str
    category: str
    answers: List[int]


@app.post("/attempt/submit")
def submit_attempt(body: SubmitAttemptRequest):
    user = get_user_by_token(body.token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # Get questions in category in a stable order
    questions = list(db["question"].find({"category": body.category})) if db else []
    if not questions:
        raise HTTPException(status_code=400, detail="No questions available for this category")

    total = len(questions)
    correct = 0
    for i, q in enumerate(questions):
        if i < len(body.answers) and body.answers[i] == q.get("correct_index"):
            correct += 1

    score = round((correct / total) * 100, 2)

    attempt_doc = Attempt(
        user_id=str(user["_id"]),
        category=body.category,
        answers=body.answers,
        correct_count=correct,
        total=total,
        score=score
    )
    attempt_id = create_document("attempt", attempt_doc)

    # Update progress summary
    prog = db["progress"].find_one({"user_id": str(user["_id"])});
    by_cat = prog.get("by_category", {}) if prog else {}
    prev = by_cat.get(body.category, {"attempts": 0, "best_score": 0, "last_score": 0})
    updated = {
        "attempts": prev.get("attempts", 0) + 1,
        "best_score": max(prev.get("best_score", 0), score),
        "last_score": score
    }
    by_cat[body.category] = updated
    if prog:
        db["progress"].update_one({"_id": prog["_id"]}, {"$set": {"by_category": by_cat, "updated_at": datetime.utcnow()}})
    else:
        db["progress"].insert_one({
            "user_id": str(user["_id"]),
            "by_category": by_cat,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        })

    return {"attempt_id": attempt_id, "score": score, "correct": correct, "total": total}


@app.get("/progress")
def get_progress(token: str):
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    prog = db["progress"].find_one({"user_id": str(user["_id"])})
    return {"by_category": prog.get("by_category", {}) if prog else {}}


# --------- Schema exposure for tooling (optional) ---------
@app.get("/schema")
def get_schema():
    return {
        "user": User.model_json_schema(),
        "question": Question.model_json_schema(),
        "attempt": Attempt.model_json_schema(),
        "progress": Progress.model_json_schema(),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
