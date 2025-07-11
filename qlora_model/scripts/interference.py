#!/usr/bin/env python3
"""
================================================================================
inference.py

Loads your fine-tuned QLoRA adapter on top of Mistral-7B-Instruct,
and runs a simple interactive loop to analyze certificates.

Author: Mihir Gupta, 2025
For AI Certificate Service POC (PKISecOPS project)
================================================================================
"""

from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel
import torch

# =================================================================================
# Configuration
# =================================================================================
BASE_MODEL = "mistralai/Mistral-7B-Instruct-v0.1"
ADAPTER_DIR = "../model_weights/"
MAX_NEW_TOKENS = 150

# =================================================================================
# Load tokenizer & model with 4-bit quantization
# =================================================================================
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4"
)

tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
tokenizer.pad_token = tokenizer.eos_token

base_model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    quantization_config=bnb_config,
    device_map="auto"
)

# Load your trained QLoRA adapters
model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)

# Ensure model on GPU
model.eval()
if torch.cuda.is_available():
    model = model.cuda()
    device = "cuda"
else:
    device = "cpu"

# =================================================================================
# Interactive loop
# =================================================================================
print("\n✅ QLoRA Cert Inspector Ready! Type 'exit' to quit.")

while True:
    question = input("\nEnter your question (about cert flaws): ").strip()
    if question.lower() in ["exit", "quit"]:
        break

    # Example placeholder PEM (or you could read from file)
    cert_context = """
-----BEGIN CERTIFICATE-----
MIIDWjCCAsOgAwIBAgIUL1M/vYxrrfKIeeVyePEBEThvDsUwDQYJKoZIhvcNAQEF
...
-----END CERTIFICATE-----
"""

    prompt = f"""### Instruction:
{question}

### Certificate:
{cert_context}

### Answer:"""

    inputs = tokenizer(prompt, return_tensors="pt").to(device)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=True,
            top_p=0.9,
            temperature=0.7
        )

    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    print("\n--- Answer ---")
    print(response[len(prompt):].strip())

