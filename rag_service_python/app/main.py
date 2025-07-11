#!/usr/bin/env python3
"""
================================================================================
FastAPI RAG Service

Loads your FAISS index + metadata, embeds incoming question, 
finds nearest paragraphs from RFCs + CAB docs, and returns them.

Run with:
    uvicorn app.main:app --reload

Author: Mihir Gupta, 2025
================================================================================
"""

from fastapi import FastAPI
from pydantic import BaseModel
import json
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

# ----------------------------
# Models
# ----------------------------
class QueryRequest(BaseModel):
    question: str
    k: int = 5

# ----------------------------
# App & global state
# ----------------------------
app = FastAPI()

print("✅ Loading SentenceTransformer model...")
model = SentenceTransformer("all-MiniLM-L6-v2")

import os

# Get the absolute path to the project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

# Define paths relative to project root
faiss_index_path = os.path.join(project_root, "knowledge_base/faiss_index/faiss_index.index")
metadata_path = os.path.join(project_root, "knowledge_base/faiss_index/metadata.json")

print(f"✅ Loading FAISS index from {faiss_index_path}...")
index = faiss.read_index(faiss_index_path)

print(f"✅ Loading metadata from {metadata_path}...")
with open(metadata_path) as f:
    metadata = json.load(f)

# ----------------------------
# Endpoints
# ----------------------------
@app.get("/")
def root():
    return {
        "name": "PKISecOPS RAG Service",
        "description": "Certificate security knowledge retrieval API",
        "endpoints": [
            {
                "path": "/",
                "method": "GET",
                "description": "This information page"
            },
            {
                "path": "/healthz",
                "method": "GET",
                "description": "Health check endpoint"
            },
            {
                "path": "/query",
                "method": "POST",
                "description": "Query the RAG system with certificate-related questions",
                "request_body": {
                    "question": "string",
                    "k": "integer (default: 5)"
                }
            },
            {
                "path": "/docs",
                "method": "GET",
                "description": "Swagger UI API documentation"
            }
        ]
    }

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.post("/query")
def query_rag(request: QueryRequest):
    query_embedding = model.encode([request.question], convert_to_numpy=True)
    D, I = index.search(query_embedding, request.k)

    results = []
    for idx in I[0]:
        item = metadata.get(str(idx))
        if item:
            results.append(item)

    return {
        "question": request.question,
        "results": results
    }
