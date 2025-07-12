#!/usr/bin/env python3
"""
Improved script to test the QLoRA model with a certificate.

- Uses a structured, checklist-style prompt for reliable, readable output.
- Adjusts generation parameters for completeness and clarity.
- Extracts and displays the answer in a user-friendly way.
"""

from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel
import torch

# =================================================================================
# Config
# =================================================================================
BASE_MODEL = "mistralai/Mistral-7B-Instruct-v0.1"
ADAPTER_DIR = "../model_weights/"
MAX_NEW_TOKENS = 768  # Increased for longer, structured output

# Sample certificate for testing
TEST_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIEQTCCAyqgAwIBAgIQTq7PCYakkQw0uFRrImthBjANBgkqhkiG9w0BAQUFADCB
ujEfMB0GA1UEChMWVmVyaVNpZ24gVHJ1c3QgTmV0d29yazEXMBUGA1UECxMOVmVy
aVNpZ24sIEluYy4xMzAxBgNVBAsTKlZlcmlTaWduIEludGVybmF0aW9uYWwgU2Vy
dmVyIENBIC0gQ2xhc3MgMzFJMEcGA1UECxNAd3d3LnZlcmlzaWduLmNvbS9DUFMg
SW5jb3JwLmJ5IFJlZi4gTElBQklMSVRZIExURC4oYyk5NyBWZXJpU2lnbjAeFw0w
ODA2MDMwMDAwMDBaFw0wOTA2MDMyMzU5NTlaMHkxCzAJBgNVBAYTAlVTMQ0wCwYD
VQQIEwRPaGlvMREwDwYDVQQHFAhDb2x1bWJ1czEXMBUGA1UEChQOSlBNb3JnYW4g
Q2hhc2UxETAPBgNVBAsUCGNpZzF3MTIzMRwwGgYDVQQDFBNyZXNvdXJjZXMuY2hh
c2UuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkIs4JV8HqzSxT7DXE
QofMi9PIkFalsxsPQvUv0Z+Fzm3KH6GXZw+drpiNZDLtJr2afhVelLAxXOWgP0GR
zg/HfqOKU7PAM/Fregf5nA9fLNbiw3nXzgoJG1YaKLpIDhAk2nvwWT4K8RkGHUWt
UB7sUOMApRHCqOobtbCDRx2ZaQIDAQABo4IBhjCCAYIwCQYDVR0TBAIwADALBgNV
HQ8EBAMCBaAwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NybC52ZXJpc2lnbi5j
b20vQ2xhc3MzSW50ZXJuYXRpb25hbFNlcnZlci5jcmwwRAYDVR0gBD0wOzA5Bgtg
hkgBhvhFAQcXAzAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy52ZXJpc2lnbi5j
b20vcnBhMDQGA1UdJQQtMCsGCWCGSAGG+EIEAQYKKwYBBAGCNwoDAwYIKwYBBQUH
AwEGCCsGAQUFBwMCMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDov
L29jc3AudmVyaXNpZ24uY29tMG4GCCsGAQUFBwEMBGIwYKFeoFwwWjBYMFYWCWlt
YWdlL2dpZjAhMB8wBwYFKw4DAhoEFEtruSiWBgy70FI4mymsSweLIQUYMCYWJGh0
dHA6Ly9sb2dvLnZlcmlzaWduLmNvbS92c2xvZ28xLmdpZjANBgkqhkiG9w0BAQUF
AAOBgQACKes0hmadREgpBLdxe1DDk5RkQEyr60Vu//qbr5QVReq2ae/DvzUIYjRO
BCKT850/gFYN+2eLB3/oUpYThM81flQP/iCXXH8jXQz5fiRJH4GJ38u5BAW5UvVi
o25SUXb3IEZeToTkVBSwgVyytew2DfTJI7EJly2FSLfRbZx5zg==
-----END CERTIFICATE-----"""

TEST_QUESTION = "List all security flaws found in this certificate."

def main():
    print("Loading model...")

    # Configure quantization
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
        bnb_4bit_quant_type="nf4"
    )

    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    tokenizer.pad_token = tokenizer.eos_token

    # Load base model with quantization
    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        use_cache=True
    )

    # Load fine-tuned QLoRA adapter
    model = PeftModel.from_pretrained(base_model, ADAPTER_DIR)
    model.eval()

    # Merge adapter weights with base model for better generation
    print("Merging adapter weights with base model...")
    try:
        model = model.merge_and_unload()
        print("✅ Successfully merged adapter weights")
    except Exception as e:
        print(f"⚠️ Could not merge adapter weights: {e}")
        print("Continuing with adapter model...")

    # Set model to evaluation mode again after merge
    model.eval()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"✅ Model loaded on {device.upper()}")

    # Structured prompt for checklist-style output
    prompt = f"""<s>[INST]
Analyze the following X.509 certificate for these security flaws:
- Expired certificate
- SHA-1 signature algorithm
- Low entropy serial number
- Short key length (less than 2048 bits)
- Missing Subject Alternative Name (SAN) extension

For each flaw, respond with either "Found" and a brief explanation, or "Not found". Use this format:

1. Expired certificate: [Found/Not found]. Explanation...
2. SHA-1 signature algorithm: [Found/Not found]. Explanation...
3. Low entropy serial number: [Found/Not found]. Explanation...
4. Short key length: [Found/Not found]. Explanation...
5. Missing SAN extension: [Found/Not found]. Explanation...

Certificate:
{TEST_CERTIFICATE}
[/INST]"""

    print("\n--- Prompt ---")
    print(prompt)
    print("\nGenerating response...")

    # Generate response
    inputs = tokenizer(prompt, return_tensors="pt").to(device)
    print(f"\nPrompt length: {len(prompt)} characters")
    print(f"Input token length: {len(inputs.input_ids[0])} tokens")

    with torch.no_grad():
        outputs = model.generate(
            input_ids=inputs.input_ids,
            attention_mask=inputs.attention_mask,
            max_new_tokens=MAX_NEW_TOKENS,
            temperature=0.0,  # Deterministic output
            do_sample=False,
            num_beams=1,      # Simpler, more natural output
            repetition_penalty=1.1,
            early_stopping=True
        )

    # Decode and print the response
    try:
        decoded = tokenizer.decode(outputs[0], skip_special_tokens=True)

        print("\n--- Input Question ---")
        print(TEST_QUESTION)

        print("\n--- Certificate (truncated) ---")
        print("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")

        print("\n--- Raw Model Output ---")
        print(decoded)

        print("\n--- Extracted Answer ---")
        # Extract the answer part after the instruction format
        if "[/INST]" in decoded:
            answer = decoded.split("[/INST]", 1)[1].strip()
        else:
            answer = decoded.strip()
        print(answer)

        # Optional: Check if all flaws are mentioned
        flaws = [
            "Expired certificate",
            "SHA-1 signature algorithm",
            "Low entropy serial number",
            "Short key length",
            "Missing SAN extension"
        ]
        missing = [f for f in flaws if f not in answer]
        if missing:
            print("\n⚠️ The following flaw categories were not mentioned in the output:")
            for f in missing:
                print(f"- {f}")

    except Exception as e:
        print(f"\n⚠️ Error processing model output: {e}")

if __name__ == "__main__":
    main()
