# Prototype: every 30 seconds update the garage status.

import binascii
import config
import cryptolib
import machine
import network
import os # for os.urandom
import time
import sys
import ssd1306
import secrets
import urequests
import io # for io.StringIO
import ujson


def do_assert(stmt, msg):
    if not stmt:
        raise Exception("assert failed with message: {}".format(msg))
    
def get_ssid():
    if in_debug_mode():
        return config.WIFI_SSID
    return config.WIFI_SSID

def get_http_endpoint():
    return "http://garage.kevinalbs.com"

def in_debug_mode ():
    btn = machine.Pin(config.DEBUG_PIN, machine.Pin.IN, machine.Pin.PULL_UP)
    if btn.value() == 0:
        return True

def show_error(display, exc, msg):
    to_display = ["{}: {}".format(msg, str(exc))]

    # Try to display the first failing line number in main.py.
    # Print exception to a StringIO.
    # Example:
    # Traceback (most recent call last):
    #     File "<stdin>", line 1, in <module>
    #     File "test.py", line 17, in <module>
    #     File "test.py", line 6, in test
    #     File "main.py", line 153, in test
    #     File "main.py", line 89, in test_http_request
    # Exception: failed to get token
    sio = io.StringIO()
    sys.print_exception(exc, sio)
    lines = sio.getvalue().split("\n")
    last_line_with_main = None
    prefix = '  File "main.py", '
    for line in lines:
        if prefix in line:
            last_line_with_main = line
    if last_line_with_main is not None:
        without_prefix = last_line_with_main[len(prefix):]
        to_display.append(without_prefix)
    
    display_lines (display, to_display)

    print("got exception")
    sys.print_exception(exc)

    led = machine.Pin(config.LED_PIN, machine.Pin.OUT)
    for _ in range(3):
        led.on()
        time.sleep(0.5)
        led.off()
        time.sleep(0.5)
    led.on()

def get_time_str ():
    (_, _, _, hour, minute, second, _, _) = time.localtime()
    return "{:02}:{:02}:{:02}".format(hour, minute, second)

def display_lines(display, lines):
    screen_height = 128
    screen_width = 64
    char_width = 4
    char_height = 8
    max_chars = screen_width // char_width
    max_lines = screen_height // char_height

    display.fill(0)
    i = 0
    for line in lines:
        while len(line) > 0:
            display.text(line[0:max_chars], 0, char_height * i)
            line = line[max_chars:]
            i += 1
            if i > max_lines:
                break

    display.show()

def try_connect_wifi():
    # Connect to WIFI
    sta_if = network.WLAN(network.STA_IF)
    # https://docs.micropython.org/en/latest/esp8266/tutorial/network_basics.html#configuration-of-the-wifi suggests connect does not block waiting for connection.
    connect_start_ns = time.time_ns()
    if not sta_if.isconnected():
        sta_if.active(True)
        sta_if.connect(get_ssid(), config.WIFI_PASSWORD)
        while not sta_if.isconnected():
            time_diff = time.time_ns() - connect_start_ns
            if time_diff > 5 * 1000 * 1000 * 1000:
                print("unable to connect to wifi after 5 seconds")
                return False
            time.sleep(.5) # Sleep to avoid spinning.
    return True

def test_wifi():
    ok = try_connect_wifi()
    if not ok:
        raise Exception("Failed to connect")

def get_token():
    endpoint = get_http_endpoint()
    resp = urequests.get(endpoint + "/get_token")
    resp_dict = resp.json()
    if "ok" not in resp_dict:
        raise Exception("No 'ok' in response: {}".format(resp.text))
    if not resp_dict["ok"]:
        raise Exception("Response not ok: {}".format(resp_dict["description"]))
    if "token" not in resp_dict:
        raise Exception("No 'token' in response: {}".format(resp.text))
    return resp_dict["token"]

def update_status(status, testing=False, health=False):
    endpoint = get_http_endpoint()
    token = get_token ()
    payload_dict = {'token': token, 'status': status}
    if testing:
        payload_dict["testing"] = True
    if health:
        payload_dict["health"] = True
    payload_plaintext = ujson.dumps(payload_dict)
    payload = encrypt(payload_plaintext.encode("utf8"))
    payload_hex = binascii.hexlify(payload)
    post_data = ujson.dumps({'payload': payload_hex })
    resp = urequests.post(endpoint + "/update_status", headers={'content-type': 'application/json'}, data=post_data)
    resp_dict = resp.json()
    if "ok" not in resp_dict:
        raise Exception("No 'ok' in response: {}".format(resp.text))
    if not resp_dict["ok"]:
        raise Exception("Response not ok: {}".format(resp_dict["description"]))

def get_status(testing=False):
    endpoint = get_http_endpoint()
    token = get_token ()
    payload_dict = {'token': token }
    if testing:
        payload_dict["testing"] = True
    payload_plaintext = ujson.dumps(payload_dict)
    payload = encrypt(payload_plaintext.encode("utf8"))
    payload_hex = binascii.hexlify(payload)
    post_data = ujson.dumps({'payload': payload_hex })
    resp = urequests.post(endpoint + "/get_status", headers={'content-type': 'application/json'}, data=post_data)
    resp_dict = resp.json()
    if "ok" not in resp_dict:
        raise Exception("No 'ok' in response: {}".format(resp.text))
    if not resp_dict["ok"]:
        raise Exception("Response not ok: {}".format(resp_dict["description"]))
    if "status" not in resp_dict:
        raise Exception("No 'status' in response: {}".format(resp.text))
    return resp_dict["status"]


def test_http_request ():
    # Test updating a testing status.
    update_status('ESP8266_test_status', testing=True)
    
    # Test getting a testing status.
    got = get_status(testing=True)
    if got != "ESP8266_test_status":
        raise Exception("Expected {}, got {}".format("ESP8266_test_status", got))

    # Test omitting a token. Expect an error.
    endpoint = get_http_endpoint()
    payload_plaintext = ujson.dumps({'testing': True})
    payload = encrypt(payload_plaintext.encode("utf8"))
    payload_hex = binascii.hexlify(payload)
    post_data = ujson.dumps({'payload': payload_hex })
    resp = urequests.post(endpoint + "/get_status", headers={'content-type': 'application/json'}, data=post_data)
    resp_dict = resp.json()
    if "ok" not in resp_dict:
        raise Exception("No 'ok' in response: {}".format(resp.text))
    if resp_dict["ok"]:
        raise Exception("Expected error, but got OK")
    if "Expected token" not in resp_dict["description"]:
        raise Exception("Expected description '{}', but got '{}'".format("Expected token", resp_dict["description"]))


def encrypt (plaintext : bytes, iv=None):
    if iv is None:
        iv = os.urandom(16)
    mode = 2 # CBC
    aes = cryptolib.aes(secrets.shared_key, mode, iv)
    block_length = 16
    padding_len = 16 - (len(plaintext) % block_length)
    # Pad to the next block_length multiple with a repeat of the padding_len.
    padding = bytearray([padding_len] * padding_len)
    output = aes.encrypt(plaintext + padding)
    # Prefix with the IV in plaintext.
    return iv + output

def decrypt (ciphertext : bytes):
    iv = ciphertext[0:16]
    mode = 2 # CBC
    aes = cryptolib.aes(secrets.shared_key, mode, iv)
    output = aes.decrypt(ciphertext)
    padding_len = output[-1]
    return output[16:-padding_len]

def test_crypto():
    # Encrypt with a fixed IV. Expect a fixed ciphertext.
    iv = bytearray([123] * 16)
    ciphertext = encrypt(b"foo", iv)
    expect = binascii.unhexlify("7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b9b4cb36dd66f061d0e211e5160c70993")
    if ciphertext != expect:
        raise Exception ("expected {}, got {}".format(binascii.hexlify(expect), binascii.hexlify(ciphertext)))
    
    # Encrypt and decrypt.
    ciphertext = encrypt(b"foo")
    plaintext = decrypt(ciphertext)
    if plaintext != b"foo":
        raise Exception ("expected {}, got {}".format(binascii.hexlify(b"foo"), binascii.hexlify(plaintext)))

def test(display):
    # Capture test name. Test functions raise exceptions on failure. Wrap exception with a helpful error.
    test_name = ""
    try:
        test_name = "WiFi (SSID={})".format(get_ssid())
        display_lines(display, ["Testing {}...".format(test_name)])
        test_wifi ()
        display_lines(display, ["Testing {}...OK".format(test_name)])
        time.sleep(.5) # To show output.

        test_name = "Crypto"
        display_lines(display, ["Testing {}...".format(test_name)])
        test_crypto ()
        display_lines(display, ["Testing {}...OK".format(test_name)])
        time.sleep(.5) # To show output.

        test_name = "HTTP"
        display_lines(display, ["Testing {}...".format(test_name)])
        test_http_request ()
        display_lines(display, ["Testing {}...OK".format(test_name)])
        time.sleep(.5) # To show output.

        display_lines(display, ["All tests passed"])
    except Exception as exc:
        show_error (display, exc, "Testing {}...failed".format(test_name))


def prompt (display, choices) -> str:
    """
    prompt displays a list of choices.
    """
    btn = machine.Pin(PIN_D5, machine.Pin.IN, machine.Pin.PULL_UP)
    RELEASED = 1
    PRESSED = 0
    btn_down_start_ms = None
    selection_index = 0

    while True:
        if btn_down_start_ms != None:
            # Button was pressed on last iteration.
            if btn.value() == RELEASED:
                # Button was just released.
                btn_down_start_ms = None
                selection_index += 1
                selection_index %= len(choices)
            elif time.ticks_ms() - btn_down_start_ms > 1000:
                # Button is long pressed. Return current choice.
                return choices[selection_index]
        elif btn.value() == PRESSED:
            btn_down_start_ms = time.ticks_ms()

        lines = ["Garage checker"]
        for idx in range(len(choices)):
            if idx == selection_index:
                lines.append(">" + choices[idx])
            else:
                lines.append(" " + choices[idx])
        display_lines(display, lines)
        
        time.sleep(.01)

PIN_D5 = 14

def load_display ():
    # Load display.
    i2c = machine.I2C(scl=machine.Pin(config.DISPLAY_SCL_PIN), sda=machine.Pin(config.DISPLAY_SDA_PIN))
    if 60 not in i2c.scan():
        raise RuntimeError('Cannot find display.')
    display = ssd1306.SSD1306_I2C(128, 64, i2c)
    return display

def is_open(reed_pin):
    return reed_pin.value() == 0

def run (display):
    status = ""
    last_healthcheck = time.ticks_ms()

    REED_SWITCH_IN = 13 # D7
    reed_pin = machine.Pin (REED_SWITCH_IN, machine.Pin.IN, machine.Pin.PULL_UP)

    while True:
        print ("tick ... {}".format(get_time_str()))
        try:
            display_lines (display, ["{}".format(status), get_time_str()])

            if is_open (reed_pin):
                new_status = "Open"
            else:
                new_status = "Closed"

            if new_status != status:
                # Status changed. Needs to be posted.
                display_lines (display, ["{}...".format(new_status), get_time_str()])
                update_status (new_status)
                status = new_status
                display_lines (display, ["{}...posted".format(new_status), get_time_str()])

            if time.ticks_ms() - last_healthcheck > 60 * 60 * 1000:
                print ("Doing health check")
                # One hour passed. Update status as a health check.
                display_lines (display, ["Health check: {}...".format(new_status), get_time_str()])
                update_status (status, health=True)
                display_lines (display, ["Health check: {}... posted".format(new_status), get_time_str()])
                last_healthcheck = time.ticks_ms()

            time.sleep(5)
        except Exception as exc:    
            show_error(display, exc, "Error (retry in 5s)")
            time.sleep(5)


def main():
    try:
        display = load_display()
        choice = prompt(display, ["Test", "Run", "Idle"])
        display_lines(display, ["Selected choice:", choice])
        if choice == "Test":
            test(display)
        elif choice == "Run":
            run(display)
        elif choice == "Idle":
            # Exit `main` to allow for shell to connect.
            return
        else:
            display_lines (display, ["Not yet implemented"])
        

    except Exception as exc:
        show_error (display, exc, "Error:")

if __name__ == "__main__":
    main()