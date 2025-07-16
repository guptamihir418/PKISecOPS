#!/usr/bin/env python3
"""
Minimal script to test QLoRA fine-tuned model on a single PEM file.
Matches your original training data format exactly:
<s>[INST] <PEM FILE> [/INST]
"""

from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel
import torch

# Config
BASE_MODEL = "mistralai/Mistral-7B-Instruct-v0.1"
ADAPTER_DIR = "../model_weights/"
MAX_NEW_TOKENS = 128  # enough for your short flaw JSON output

# Load a sample PEM cert
TEST_CERTIFICATE = """-----BEGIN CERTIFICATE----- MIIEWjCCA8OgAwIBAgIKFebYyAAAAABaNzANBgkqhkiG9w0BAQUFADBGMQswCQYD VQQGEwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzEiMCAGA1UEAxMZR29vZ2xlIElu dGVybmV0IEF1dGhvcml0eTAeFw0xMjA1MzAxNDAwNTFaFw0xMzA1MzAxNDEwNTFa MGwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1N b3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMRswGQYDVQQDExJzYW5k Ym94Lmdvb2dsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKrHA6tV jUiMLQXecRoEhDDx2jLfrUWJ718Tj8Jj8I++4igBI0yMOKoCNvRAakW0feKMzh70 UFQRK0Ni0ZXQmznUNVOoqm5A2XBUURjc2sucrLOkCqIYtggMfEwJb70wapgjDvBk 5xb+b5vN1hEVCFPE5DMxtnPd7RUeGkTYTW2JAgMBAAGjggInMIICIzAdBgNVHSUE FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFHky5DFBdCVd3s3DyZ77 StTQUPV4MB8GA1UdIwQYMBaAFL/AMOv1QxE+Z7qekfv8atrjaxIkMFsGA1UdHwRU MFIwUKBOoEyGSmh0dHA6Ly93d3cuZ3N0YXRpYy5jb20vR29vZ2xlSW50ZXJuZXRB dXRob3JpdHkvR29vZ2xlSW50ZXJuZXRBdXRob3JpdHkuY3JsMGYGCCsGAQUFBwEB BFowWDBWBggrBgEFBQcwAoZKaHR0cDovL3d3dy5nc3RhdGljLmNvbS9Hb29nbGVJ bnRlcm5ldEF1dGhvcml0eS9Hb29nbGVJbnRlcm5ldEF1dGhvcml0eS5jcnQwgfwG A1UdEQSB9DCB8YISc2FuZGJveC5nb29nbGUuY29tghAqLmdvb2dsZXBsZXguY29t ghQqLnNhbmRib3guZ29vZ2xlLmNvbYIcKi5wcm9tLXFhLnNhbmRib3guZ29vZ2xl LmNvbYIYKi5zYW5kYm94Lmdvb2dsZWFwaXMuY29tggsqLmduZ2pkLmNvbYIZKi5k b2NzLnNhbmRib3guZ29vZ2xlLmNvbYIaKi5kcml2ZS5zYW5kYm94Lmdvb2dsZS5j b22CGyouc2NyaXB0LnNhbmRib3guZ29vZ2xlLmNvbYIaKi5zaXRlcy5zYW5kYm94 Lmdvb2dsZS5jb20wDQYJKoZIhvcNAQEFBQADgYEAET9MmgfSKP9yGx8ctWii8FEZ FVLlXTMNn1tnG+/F9YGwcN8sm8H1Zuk4hko/W80WfeqmCZOKZdLeZF2YENu/SmAf FkL7T+mGkU/UoS0gbhNTn+dYOAJXMiNkAIuYG++W2mJTD2gRqdDiQ0ZufjIr2h4W FmpCFhx6gF90oMcBo2I= -----END CERTIFICATE----- """


def main():
    print("Loading tokenizer and model...")

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
        device_map="auto",
        trust_remote_code=True
    )

    model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
    model.eval()
    model = model.merge_and_unload()  # combine LoRA into main weights
    model.eval()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"✅ Loaded model on {device.upper()}")

    # EXACT SAME format as your training jsonl:
    prompt = f"<s>[INST] {TEST_CERTIFICATE} [/INST]"

    inputs = tokenizer(prompt, return_tensors="pt").to(device)

    with torch.no_grad():
        outputs = model.generate(
            input_ids=inputs.input_ids,
            attention_mask=inputs.attention_mask,
            max_new_tokens=MAX_NEW_TOKENS,
            temperature=0.0,
            do_sample=False
        )

    # Decode
    decoded = tokenizer.decode(outputs[0], skip_special_tokens=True)

    print("\n--- Model output ---")
    print(decoded)

    # Extract just the JSON-like portion after [/INST]
    if "[/INST]" in decoded:
        answer = decoded.split("[/INST]", 1)[1].strip()
        print("\n--- Extracted flaw JSON ---")
        print(answer)
    else:
        print("\n(⚠️ Could not find [/INST] split; raw output above)")

if __name__ == "__main__":
    main()
