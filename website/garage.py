from flask import Flask, request, render_template
from werkzeug.exceptions import BadRequest
import appsecrets
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
import datetime
import time
import pathlib
import threading
from werkzeug.exceptions import HTTPException

app = Flask(__name__)

# Create empty data files if they do not already exist.
for path in [pathlib.Path("testdata"), pathlib.Path("data")]:
    if not path.exists():
        path.mkdir()
    status_file = path / "status.txt"
    if not status_file.exists():
        status_file.touch()
    log_file = path / "log.txt"
    if not log_file.exists():
        log_file.touch()

def encrypt (plaintext : bytes, iv=None):
    if iv is None:
        iv = os.urandom(16)
    cipher = Cipher(algorithms.AES256(appsecrets.shared_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    output = encryptor.update(plaintext)
    block_length = 16
    padding_len = 16 - (len(plaintext) % block_length)
    # Pad to the next block_length multiple with a repeat of the padding_len.
    padding = bytearray([padding_len] * padding_len)
    output += encryptor.update(padding)
    output += encryptor.finalize()
    # Prefix with the IV in plaintext.
    return iv + output
def decrypt (ciphertext : bytes):
    iv = ciphertext[0:16]
    cipher = Cipher(algorithms.AES256(appsecrets.shared_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    output = decryptor.update(ciphertext[16:])
    output += decryptor.finalize()
    padding_len = output[-1]
    return output[0:-padding_len]

# `token_cache` is used to prevent replay attacks.
# A token is only valid for one-time use.
# A token is cached for a fixed time period.
token_cache = {}
expire_after_ns = 5 * 60 * 1000 * 1000 * 1000 # Five minutes.
token_cache_mutex = threading.Lock()
next_token_id = 0

def get_and_expire_tokens () -> str:
    global next_token_id, expire_after_ns
    with token_cache_mutex:
        # Remove expired cached tokens.
        expired_token_ids = []
        for token_id, token in token_cache.items():
            token_dict = json.loads(token)
            if time.time_ns() - token_dict["time"] > expire_after_ns:
                expired_token_ids.append(token_id)
        for token_id in expired_token_ids:
            print ("Removing expired token: {}".format(token_id))
            del token_cache[token_id]
        token_id = next_token_id
        next_token_id += 1
        token = json.dumps({"time": time.time_ns(), "id": token_id })
        token_cache[token_id] = token
        return token

def check_and_remove_token (token : str):
    global expire_after_ns
    with token_cache_mutex:
        token_dict = json.loads(token)
        if time.time_ns() - token_dict["time"] > expire_after_ns:
            raise BadRequest("Token too old. Get new token and retry request.")
        # If token is in cache, validate it is recent enough.
        if token_dict["id"] not in token_cache:
            raise BadRequest("Unrecognized token. Token may have expired. Get new token and retry request.")
        del token_cache[token_dict["id"]]
        return True

def decrypt_payload (payload_hex: str):
    try:
        payload_bytes = bytes.fromhex (payload_hex)
        payload_str = decrypt(payload_bytes)
        return json.loads(payload_str)
    except Exception as exc:
        raise BadRequest("Failed to decrypt 'payload'") from exc

@app.route("/get_token")
def get_token_req():
    return {"ok": True, "token": get_and_expire_tokens() }

@app.route("/hello")
def hello():
    return "Hello"

@app.route("/update_status", methods=["post"])
def update_status():
    body = request.json
    if not "payload" in body:
        raise BadRequest("Expected payload in JSON body.")
    # Decrypt payload
    payload = decrypt_payload(body["payload"])
    if not "token" in payload:
        raise BadRequest("Expected token in payload.")
    check_and_remove_token(payload["token"])
    
    # Remove "token" from payload.
    del payload["token"]
    # Add UNIX timestamp to payload.
    payload["unix_timestamp"] = time.time()
    tz = datetime.timezone(datetime.timedelta(hours=-5))
    payload["human_time"] = datetime.datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    if app.testing or "testing" in payload and payload["testing"]:
        # Do not update production data.
        path = pathlib.Path("testdata")
    else:
        path = pathlib.Path("data")
    
    with open(path / "log.txt", "a") as file_log:
        file_log.write(datetime.datetime.now().isoformat() + " " + json.dumps(payload) + "\n")
    if "health" in payload and payload["health"]:
        # Health check only. Do not update status.
        with open (path / "last_health.txt", "w") as file_last_health:
            file_last_health.write(json.dumps(payload))
    else:
        # Not a health check. Update status.
        with open(path / "status.txt", "w") as file_status:
            file_status.write(json.dumps(payload))
        if payload["status"] == "Open":
            with open(path / "last_open.txt", "w") as file_last_open:
                file_last_open.write(json.dumps(payload))

    return {"ok": True}

@app.route("/get_status", methods=["post"])
def get_status():
    body = request.json
    if not "payload" in body:
        raise BadRequest("Expected payload in JSON body.")
    payload = decrypt_payload(body["payload"])
    if not "token" in payload:
        raise BadRequest("Expected token in payload.")
    check_and_remove_token(payload["token"])

    if app.testing or "testing" in payload and payload["testing"]:
        # Do not update production data.
        path = pathlib.Path("testdata")
    else:
        path = pathlib.Path("data")
    
    with open(path / "status.txt", "r") as file_status:
        got = file_status.read()
        got = json.loads(got)
        got["ok"] = True
        return got
    
@app.route("/")
def home():
    if app.testing or request.args.get("testing", "false") == "true":
        # Do not update production data.
        path = pathlib.Path("testdata")
    else:
        path = pathlib.Path("data")

    last_open_path = path / "last_open.txt"
    last_open_unix_timestamp_secs = None
    if last_open_path.exists():
        last_open_text = last_open_path.read_text()
        last_open_dict = json.loads(last_open_text)
        last_open_unix_timestamp_secs = int(last_open_dict["unix_timestamp"])

    last_health_path = path / "last_health.txt"
    last_health_unix_timestamp_secs = None
    last_health_age_minutes = 0
    if last_health_path.exists():
        last_health_text = last_health_path.read_text()
        last_health_dict = json.loads(last_health_text)
        last_health_unix_timestamp_secs = int(last_health_dict["unix_timestamp"])
        last_health_age_secs = time.time() - last_health_dict["unix_timestamp"]
        last_health_age_minutes = int(last_health_age_secs / 60)


    with open(path / "status.txt", "r") as file_status:
        status_text = file_status.read()
        status_dict = json.loads(status_text)

    age = time.time() - status_dict["unix_timestamp"]
    age_minutes = int(age / 60)

    return render_template("index.html",
                           status=status_dict["status"],
                           age_minutes=age_minutes,
                           last_updated_secs=int(status_dict["unix_timestamp"]),
                           last_open_unix_timestamp_secs=last_open_unix_timestamp_secs,
                           last_health_unix_timestamp_secs=last_health_unix_timestamp_secs,
                           last_health_age_minutes=last_health_age_minutes
                           )

@app.errorhandler(HTTPException)
def handle_exception(e):
    if request.path == "/":
        # Use default exception handling.
        raise e
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps({
        "ok": False,
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response
