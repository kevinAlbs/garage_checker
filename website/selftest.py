
from garage import app
import garage
from flask.testing import FlaskClient
import unittest
import json
import time

app.config.update({
    "TESTING": True,
})

class TestApp (unittest.TestCase):
    def test_hello (self):
        with app.test_client() as client:
            resp = client.get("/hello")
            self.assertEqual(resp.text, "Hello")

    def test_get_token (self):
        with app.test_client() as client:
            resp = client.get("/get_token")
            got = resp.json
            self.assertEqual(got["ok"], True, "expected ok, got: {}".format(got))
            self.assertIsNotNone(resp.json["token"])

    def get_token(self, client):
        resp = client.get("/get_token")
        return resp.json["token"]

    def test_update_status (self):
        with app.test_client() as client:
            payload = garage.encrypt(json.dumps({
                "status": "Open",
                "token": self.get_token(client)
            }).encode("utf8")).hex()
            resp = client.post("/update_status", json={
                "payload": payload
            })
            self.assertEqual(resp.status_code, 200, "Expected HTTP 200, got {} with text:\n{}".format(resp.status_code, resp.text))
            got = resp.json
            self.assertEqual(got["ok"], True, "expected ok, got: {}".format(got))

    def test_update_and_get_status (self):
        with app.test_client() as client:
            payload = garage.encrypt(json.dumps({
                "status": "foo",
                "token": self.get_token(client)
            }).encode("utf8")).hex()
            resp = client.post("/update_status", json={
                "payload": payload
            })
            got = resp.json
            self.assertEqual(got["ok"], True, "expected ok, got: {}".format(got))
            payload = garage.encrypt(json.dumps({
                "token": self.get_token(client)
            }).encode("utf8")).hex()
            resp = client.post("/get_status", json={
                "payload": payload
            })
            got = resp.json
            self.assertEqual(got["ok"], True, "expected ok, got: {}".format(got))
            self.assertEqual(got["status"], "foo", "expected foo, got: {}".format(got))

    def test_rejects_without_token(self):
        with app.test_client() as client:
            payload = garage.encrypt(json.dumps({
                "status": "Open",
            }).encode("utf8")).hex()
            resp = client.post("/update_status", json={
                "payload": payload
            })
            self.assertEqual(resp.status_code, 400)
            self.assertIn('Expected token in payload', resp.text)

    def test_rejects_expired_token(self):
        with app.test_client() as client:
            token = self.get_token(client)
            # Set an expired time on the token.
            token_dict = json.loads(token)
            token_dict["time"] = time.time_ns() - garage.expire_after_ns - 1
            token = json.dumps(token_dict)

            payload = garage.encrypt(json.dumps({
                "status": "Open",
                "token": token
            }).encode("utf8")).hex()
            resp = client.post("/update_status", json={
                "payload": payload
            })
            self.assertEqual(resp.status_code, 400, "Expected HTTP 400, got {} with text:\n{}".format(resp.status_code, resp.text))
            self.assertIn("Token too old", resp.text)

    def test_rejects_reused_token(self):
        with app.test_client() as client:
            token = self.get_token(client)
            payload = garage.encrypt(json.dumps({
                "status": "Open",
                "token": token
            }).encode("utf8")).hex()
            resp = client.post("/update_status", json={
                "payload": payload
            })
            self.assertEqual(resp.status_code, 200, "Expected HTTP 200, got {} with text:\n{}".format(resp.status_code, resp.text))
            got = resp.json
            self.assertEqual(got["ok"], True, "expected ok, got: {}".format(got))

            payload = garage.encrypt(json.dumps({
                "status": "Open",
                "token": token
            }).encode("utf8")).hex()
            resp = client.post("/update_status", json={
                "payload": payload
            })
            self.assertEqual(resp.status_code, 400, "Expected HTTP 400, got {} with text:\n{}".format(resp.status_code, resp.text))
            self.assertIn("Unrecognized token", resp.text)

    def test_cached_expired_tokens_are_removed(self):
        with app.test_client() as client:
            token1 = self.get_token(client)

            # Reduce expiration time on server.
            original_expire_after_ns = garage.expire_after_ns
            garage.expire_after_ns = 1
            time.sleep(.01) # Sleep for .01s.

            # Get another token. Expect server to remove expired token1 from cache.
            token2 = self.get_token(client)
            
            # Restore expiration time on server.
            garage.expire_after_ns = original_expire_after_ns

            # Expect using token1 to fail (was removed from cache).
            payload = garage.encrypt(json.dumps({
                "status": "Open",
                "token": token1
            }).encode("utf8")).hex()
            resp = client.post("/update_status", json={
                "payload": payload
            })
            self.assertEqual(resp.status_code, 400, "Expected HTTP 400, got {} with text:\n{}".format(resp.status_code, resp.text))
            self.assertIn("Unrecognized token", resp.text)

            # Expect using token2 to succeed.
            payload = garage.encrypt(json.dumps({
                "status": "open",
                "token": token2
            }).encode("utf8")).hex()
            resp = client.post("/update_status", json={
                "payload": payload
            })
            self.assertEqual(resp.status_code, 200, "Expected HTTP 200, got {} with text:\n{}".format(resp.status_code, resp.text))
            got = resp.json
            self.assertEqual(got["ok"], True, "expected ok, got: {}".format(got))


    def test_encrypt (self):
        iv = bytearray([123] * 16)
        ciphertext = garage.encrypt(b"foo", iv)
        expect = bytes.fromhex("7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b9b4cb36dd66f061d0e211e5160c70993")
        self.assertEqual(ciphertext, expect)
        
    def test_encrypt_decrypt (self):
        ciphertext = garage.encrypt(b"foo")
        plaintext = garage.decrypt(ciphertext)
        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(plaintext, b"foo")

    def test_update_health (self):
        with app.test_client() as client:
            payload = garage.encrypt(json.dumps({
                "status": "Open",
                "token": self.get_token(client),
                "health": True
            }).encode("utf8")).hex()
            resp = client.post("/update_status", json={
                "payload": payload
            })
            self.assertEqual(resp.status_code, 200, "Expected HTTP 200, got {} with text:\n{}".format(resp.status_code, resp.text))
            got = resp.json
            self.assertEqual(got["ok"], True, "expected ok, got: {}".format(got))
        
    def test_health_does_not_update_status (self):
        with app.test_client() as client:
            # Update status to "foo".
            payload = garage.encrypt(json.dumps({
                "status": "foo",
                "token": self.get_token(client)
            }).encode("utf8")).hex()
            resp = client.post("/update_status", json={
                "payload": payload
            })
            got = resp.json
            self.assertEqual(got["ok"], True, "expected ok, got: {}".format(got))

            # Send health check with status "bar".
            payload = garage.encrypt(json.dumps({
                "status": "bar",
                "token": self.get_token(client),
                "health": True
            }).encode("utf8")).hex()
            resp = client.post("/update_status", json={
                "payload": payload
            })
            got = resp.json
            self.assertEqual(got["ok"], True, "expected ok, got: {}".format(got))

            payload = garage.encrypt(json.dumps({
                "token": self.get_token(client)
            }).encode("utf8")).hex()
            resp = client.post("/get_status", json={
                "payload": payload
            })
            got = resp.json
            self.assertEqual(got["ok"], True, "expected ok, got: {}".format(got))
            self.assertEqual(got["status"], "foo", "expected foo, got: {}".format(got))
if __name__ == "__main__":
    unittest.main()
    