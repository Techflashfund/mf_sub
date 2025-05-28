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
import logging

logger = logging.getLogger(__name__)
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


# def decrypt_challenge(encryption_private_key_b64: str, ondc_public_key_b64: str, challenge_string_b64: str) -> str:
#     # Load keys
#     private_key = serialization.load_der_private_key(
#         b64decode(encryption_private_key_b64),
#         password=None,
#     )
#     public_key = serialization.load_der_public_key(
#         b64decode(ondc_public_key_b64)
#     )

#     # Derive shared key
#     shared_key = private_key.exchange(public_key)

#     # Decrypt AES-ECB
#     cipher = AES.new(shared_key, AES.MODE_ECB)
#     decrypted = unpad(cipher.decrypt(b64decode(challenge_string_b64)), AES.block_size)

#     return decrypted.decode('utf-8')



# @csrf_exempt
# def on_subscribe(request):
#     if request.method == 'POST':
#         try:
#             body = json.loads(request.body)
#             challenge_string = body["message"]["challenge"]
#             logger.info(f"Challenge String: {challenge_string}")


#             # Use ONDC public key for the correct environment
#             ondc_public_key = "MCowBQYDK2VuAyEAa9Wbpvd9SsrpOZFcynyt/TO3x0Yrqyys4NUGIvyxX2Q="  # pre-prod
#             encryption_private_key = os.getenv("ENCRYPTION_PRIVATE_KEY")

#             if not encryption_private_key:
#                 return JsonResponse({"error": "Missing ENCRYPTION_PRIVATE_KEY env variable"}, status=500)

#             answer = decrypt_challenge(ondc_public_key, encryption_private_key, challenge_string)

#             return JsonResponse({
#                 "answer": answer
#             })

#         except Exception as e:
#             return JsonResponse({"error": str(e)}, status=400)

#     return JsonResponse({"error": "Invalid method"}, status=405)


import os
import json
import base64
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ONDC_PUBLIC_KEY_BASE64 = "MCowBQYDK2VuAyEAa9Wbpvd9SsrpOZFcynyt/TO3x0Yrqyys4NUGIvyxX2Q="

def decrypt_challenge(encrypted_challenge, shared_key):
    cipher = AES.new(shared_key, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_challenge))
    return unpad(decrypted_bytes, AES.block_size).decode('utf-8')

import base64
import json
import traceback
import logging

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from cryptography.hazmat.primitives import serialization
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

logging.basicConfig(level=logging.DEBUG)

@csrf_exempt
def on_subscribe(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=400)

    try:
        data = json.loads(request.body)
        encrypted_challenge = data.get("challenge")
        if not encrypted_challenge:
            return JsonResponse({"error": "Missing 'challenge' in request"}, status=400)

        logging.debug(f"Encrypted challenge (base64): {encrypted_challenge}")

        # Load your private key from DER base64 string (hardcoded here for demo)
        private_key_der = base64.b64decode("MC4CAQAwBQYDK2VuBCIEIADbh3FyDd79n+ZVLBoblozxS9TC/qO+0XLPJA6Ca8xV")
        private_key = serialization.load_der_private_key(private_key_der, password=None)

        # Load ONDC public key (staging, DER base64)
        ondc_public_key_der = base64.b64decode("MCowBQYDK2VuAyEAduMuZgmtpjdCuxv+Nc49K0cB6tL/Dj3HZetvVN7ZekM=")
        ondc_public_key = serialization.load_der_public_key(ondc_public_key_der)

        # Perform X25519 key exchange to get shared key
        shared_key = private_key.exchange(ondc_public_key)
        logging.debug(f"Shared key (hex): {shared_key.hex()}")

        encrypted_bytes = base64.b64decode(encrypted_challenge)
        logging.debug(f"Encrypted challenge bytes (hex): {encrypted_bytes.hex()}")

        # AES ECB decrypt
        cipher = AES.new(shared_key, AES.MODE_ECB)
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        logging.debug(f"Decrypted bytes (hex): {decrypted_bytes.hex()}")

        # Try unpadding, fallback to stripping null bytes if padding is incorrect
        try:
            challenge_answer = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
        except ValueError:
            logging.warning("PKCS#7 padding incorrect, using fallback decoding")
            challenge_answer = decrypted_bytes.rstrip(b"\x00").decode('utf-8', errors='ignore')

        logging.debug(f"Decrypted challenge answer (fallback applied if needed): {challenge_answer}")

        return JsonResponse({"answer": challenge_answer})

    except Exception as e:
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)




import os
import json
import base64
import requests
from datetime import datetime, timedelta
from nacl.signing import SigningKey
from nacl.bindings import crypto_sign_ed25519_sk_to_seed
from dotenv import load_dotenv
from .cryptic_utils import create_authorisation_header
load_dotenv()
from datetime import datetime, timezone

# Load keys and config from .env
SIGNING_PRIVATE_KEY_BASE64 = os.getenv("PRIVATE_KEY")
SIGNING_PUBLIC_KEY = os.getenv("PUBLIC_KEY")
ENCRYPTION_PUBLIC_KEY = os.getenv("ENCRYPTION_PUBLIC_KEY")
SUBSCRIBER_ID = os.getenv("SUBSCRIBER_ID")
UNIQUE_KEY_ID = os.getenv("UNIQUE_KEY_ID")
request_id="f5afc11d-c789-4079-949c-8bd4d23a8571"

def timestamp(date=None):
    if date is None:
        date = datetime.now(timezone.utc)  # current time in UTC
    # Returns ISO 8601 format with 'Z' for UTC timezone
    return date.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
def get_valid_until_timestamp():
    current_date = datetime.now(timezone.utc)
    # Add 2 years using timedelta (approximate as 730 days)
    # For exact 2 years accounting leap years, use dateutil.relativedelta
    from dateutil.relativedelta import relativedelta
    future_date = current_date + relativedelta(years=2)
    return future_date.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


@csrf_exempt
def subscribe(request):
    if request.method == 'POST':
        payload={
    "context": {
        "operation": {
            "ops_no": 1
        }
    },
    "message": {
        "request_id":"f5afc11d-c789-4079-949c-8bd4d23a8571",
        "timestamp": timestamp(),
        "entity": {
            "gst": {
                "legal_entity_name": "BANCWISE TECHNOLOGIES LLP",
                "business_address": "51/1702, First Floor, Civil Lane Road, West Fort, Thrissur - Kerala -680006, IN",
                "city_code": ["std:487"],
                "gst_no": "32ABDFB1579P1Z6"
            },
            "pan": {
                "name_as_per_pan": "BANCWISE TECHNOLOGIES LLP",
                "pan_no": "ABDFB1579P",
                "date_of_incorporation": "10/06/2024"
            },
            "name_of_authorised_signatory": "SIJO PAUL E",
            "address_of_authorised_signatory": "2/1384, Plot No 326, 15th Street, Harinagar, P O Punkunnam, Thrissur- 680002, Kerala, India",
            "email_id": "sijo.paul@flashfund.in",
            "mobile_no": 9995103430,
            "country": "IND",
            "subscriber_id":"investment.preprod.vyable.in",
            "unique_key_id": "b2a8f240-c280-4399-8979-1d13de9a64a0",
            "callback_url":"/",
            "key_pair": {
                "signing_public_key":"ZC4WOXoQgoAmxZPz5VqobhDc4l05A9Lh+TWeKtwC3co=",
                "encryption_public_key":"MCowBQYDK2VuAyEAVFXINjXoWGPZ4zshbPwugbm9A932PjH3fey6D3nvOxk=",
                "valid_from":timestamp(),
                "valid_until":get_valid_until_timestamp()
            }
        },
        "network_participant": [
            {
                "subscriber_url":"/",
                "domain": "ONDC:FIS14",
                "type": "buyerApp",
                "msn": False,
                "city_code": ["std:487"]
            }
        ]
    }
}       

        json_payload = json.dumps(payload, separators=(',', ':'))
        authorization_header = create_authorisation_header(json_payload)

        headers = {
            "Content-Type": "application/json",
            "Authorization": authorization_header
        }

        response = requests.post(
            "https://preprod.registry.ondc.org/ondc/subscribe",
            headers=headers,
            data=json_payload
        )
        print(response)
        return JsonResponse({
            "status_code": response.status_code,
            "response": response.json() if response.headers.get('Content-Type') == 'application/json' else response.text
        })

    return HttpResponse("Only POST method is allowed.", status=405)


