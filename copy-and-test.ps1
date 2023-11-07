# Copy files.
rshell -a --port COM3 "cp main.py config.py test.py secrets.py /pyboard"

# Run tests.
rshell -a --port COM3 "repl ~ import test ~"