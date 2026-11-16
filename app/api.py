import hmac
import hashlib
import os
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException


load_dotenv()

secret_token = os.environ["WEBHOOK_SECRET"]


app = FastAPI()


@app.post("/webhooks/github")
async def get_webhook(request: Request):
    raw_body = await request.body()
    signature_header = request.headers.get("X-Hub-Signature-256")

    verify_signature(
        raw_body, secret_token=secret_token, signature_header=signature_header
    )

    event_header = request.headers.get("X-Github-Event")

    if event_header != "issues":
        print("event_header != issues => request ingnored 200")
        return {"status": "ignored"}

    payload = await request.json()

    action = payload["action"]
    if action != "opened":
        print("action != opened => request ingnored 200")
        return {"status": "ignored"}

    print("issue received 200")
    return {"received": True}


def verify_signature(payload_body, secret_token, signature_header):
    if not signature_header:
        raise HTTPException(
            status_code=403, detail="x-hub-signature-256 header is missing!"
        )

    hash_object = hmac.new(
        secret_token.encode("utf-8"), msg=payload_body, digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()

    if not hmac.compare_digest(expected_signature, signature_header):
        raise HTTPException(status_code=403, detail="Request signatures didnt match")
