#!/usr/bin/env python3
"""
================================================================================
build_faiss.py

Downloads RFCs + CA/B documents directly from the web using WebBaseLoader,
splits into clean paragraphs, encodes them with SentenceTransformer,
and builds a FAISS index for fast similarity search.

Also writes a metadata.json that maps index IDs to their paragraph + source.

Run:
    python3 build_faiss.py

Author: Mihir Gupta, 2025
================================================================================
"""

import json
import faiss
import numpy as np
from langchain.document_loaders import WebBaseLoader
from sentence_transformers import SentenceTransformer

# ----------------------------
# CONFIG
# ----------------------------
urls = [
    "https://datatracker.ietf.org/doc/html/rfc5280",
    "https://datatracker.ietf.org/doc/html/rfc6818",
    "https://datatracker.ietf.org/doc/html/rfc9549",
    "https://datatracker.ietf.org/doc/html/rfc9598",
    "https://datatracker.ietf.org/doc/html/rfc9608",
    "https://datatracker.ietf.org/doc/html/rfc9618",
    "https://cabforum.org/baseline-requirements-documents/",
    "https://cabforum.org/working-groups/server/baseline-requirements/documents/CA-Browser-Forum-TLS-BR-2.1.5.pdf"
]

OUTPUT_DIR = "../faiss_index/"
INDEX_FILE = OUTPUT_DIR + "faiss_index.index"
META_FILE  = OUTPUT_DIR + "metadata.json"

# ----------------------------
# 1️⃣ Load documents from web
# ----------------------------
print("✅ Loading documents from the web...")
docs = []
for url in urls:
    loader = WebBaseLoader(url)
    loaded = loader.load()
    print(f"Loaded {len(loaded)} from {url}")
    for doc in loaded:
        docs.append({
            "content": doc.page_content,
            "source": url
        })

# ----------------------------
# 2️⃣ Split into paragraphs
# ----------------------------
print("✅ Splitting into paragraphs...")
paragraphs = []
metadata = {}
idx = 0
for doc in docs:
    for para in doc["content"].split("\n\n"):
        clean_para = para.strip()
        if len(clean_para) < 50:  # skip very short
            continue
        paragraphs.append(clean_para)
        metadata[idx] = {
            "text": clean_para,
            "source": doc["source"]
        }
        idx += 1

print(f"Total paragraphs: {len(paragraphs)}")

# ----------------------------
# 3️⃣ Embed paragraphs
# ----------------------------
print("✅ Encoding with sentence-transformers...")
model = SentenceTransformer("all-MiniLM-L6-v2")
embeddings = model.encode(paragraphs, convert_to_numpy=True, show_progress_bar=True)

# ----------------------------
# 4️⃣ Build FAISS index
# ----------------------------
print("✅ Building FAISS index...")
dim = embeddings.shape[1]
index = faiss.IndexFlatL2(dim)
index.add(embeddings)

# ----------------------------
# 5️⃣ Save index and metadata
# ----------------------------
print("✅ Saving FAISS index & metadata...")
import os
os.makedirs(OUTPUT_DIR, exist_ok=True)
faiss.write_index(index, INDEX_FILE)

with open(META_FILE, "w") as f:
    json.dump(metadata, f, indent=2)

print(f"🎉 Done! Wrote index to {INDEX_FILE} and metadata to {META_FILE}")
