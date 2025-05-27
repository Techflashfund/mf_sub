# import uuid
# import base64
# from nacl.signing import SigningKey

# request_id = str(uuid.uuid4())
# print("Request ID:", request_id)

# import base64
# from nacl.signing import SigningKey
# from nacl.bindings import crypto_sign_ed25519_sk_to_seed

# # Base64 encoded full private key (private+public)
# private_key_base64 = "UM13amFAflK5Zok4dJylHEY3pY3+X/w+1FhiG6Lc8CNkLhY5ehCCgCbFk/PlWqhuENziXTkD0uH5NZ4q3ALdyg=="

# # The request_id you will use in payload
# request_id = "f5afc11d-c789-4079-949c-8bd4d23a8571"  

# # Decode and get the 32 bytes seed
# private_key_bytes = base64.b64decode(private_key_base64)
# seed = crypto_sign_ed25519_sk_to_seed(private_key_bytes)
# signing_key = SigningKey(seed)

# # Sign the request_id
# signed = signing_key.sign(request_id.encode())

# # Base64 encode the signature
# signature_base64 = base64.b64encode(signed.signature).decode()

# print("SIGNED_UNIQUE_REQ_ID =", signature_base64)
# /