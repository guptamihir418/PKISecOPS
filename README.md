# PKISecOPS

A toolkit for certificate security operations and analysis with a RAG (Retrieval Augmented Generation) service for certificate security knowledge.

## Project Structure

- **rag_service_python/**: FastAPI service for certificate security knowledge retrieval
- **knowledge_base/**: Contains FAISS index and scripts to build the knowledge base
- **qlora_model/**: Scripts for fine-tuning models with QLoRA

## Features

- **Certificate Security Knowledge Retrieval**: Query the RAG system with certificate-related questions
- **FAISS Vector Database**: Fast similarity search for certificate security information
- **Web-based Knowledge Sources**: Automatically downloads and indexes RFCs and CA/B Forum documents

## Getting Started

### Prerequisites

```bash
pip install -r requirements.txt
```

### Building the Knowledge Base

```bash
cd knowledge_base/scripts
python build_faiss.py
```

### Running the RAG Service

```bash
cd rag_service_python
uvicorn app.main:app --reload
```

The service will be available at http://127.0.0.1:8000

## API Endpoints

- **/** - Information about the API
- **/healthz** - Health check endpoint
- **/query** - Query the RAG system with certificate-related questions
- **/docs** - Swagger UI API documentation

## Example Query

```bash
curl -X POST "http://127.0.0.1:8000/query" \
     -H "Content-Type: application/json" \
     -d '{"question": "What are common security flaws in certificates?", "k": 5}'
```

## Certificate Data Structure

The JSON files in this project contain certificate data with the following structure:

```json
{
  "pem": "-----BEGIN CERTIFICATE-----\n...",
  "flaws": ["expired", "sha1_signature", ...]
}
```

## License

MIT
