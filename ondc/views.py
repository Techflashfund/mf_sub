from django.shortcuts import render,HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import os
import json
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from dotenv import load_dotenv

load_dotenv()
# Create your views here.


def ondc_site_verification(request):
    return HttpResponse(
        f"""
<html>
    <head>
        <meta name='ondc-site-verification' content='/sbFqr6upS6Edb/VT20FEbBGOPzrVcJzGXVxmMG5d9zbbPWR/5+TC+dN3OTCK3l2OtgDNdHPaqOSJtZk+V9JCg==' />
    </head>
    <body>
        ONDC Site Verification Page
    </body>
</html>"""
    )


def decrypt_challenge(encryption_private_key_b64: str, ondc_public_key_b64: str, challenge_string_b64: str) -> str:
    # Load keys
    private_key = serialization.load_der_private_key(
        b64decode(encryption_private_key_b64),
        password=None,
    )
    public_key = serialization.load_der_public_key(
        b64decode(ondc_public_key_b64)
    )

    # Derive shared key
    shared_key = private_key.exchange(public_key)

    # Decrypt AES-ECB
    cipher = AES.new(shared_key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(b64decode(challenge_string_b64)), AES.block_size)

    return decrypted.decode('utf-8')



@csrf_exempt
def on_subscribe(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body)
            challenge_string = body["message"]["challenge"]
            print("Challenge String:", challenge_string)

            # Use ONDC public key for the correct environment
            ondc_public_key = "MCowBQYDK2VuAyEAa9Wbpvd9SsrpOZFcynyt/TO3x0Yrqyys4NUGIvyxX2Q="  # pre-prod
            encryption_private_key = os.getenv("ENCRYPTION_PRIVATE_KEY")

            if not encryption_private_key:
                return JsonResponse({"error": "Missing ENCRYPTION_PRIVATE_KEY env variable"}, status=500)

            answer = decrypt_challenge(ondc_public_key, encryption_private_key, challenge_string)

            return JsonResponse({
                "answer": answer
            })

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)

    return JsonResponse({"error": "Invalid method"}, status=405)