import main

def test():
    print ("Running tests ... begin")
    display = main.load_display()
    main.test(display)
    print ("Tests passed.")
    print ("Running tests ... end")

# Do not hide behind a `if __name__ == "__main__"`
# The `repl` command is used to automate tests.
# The `repl` command appears to only accept one line of input.
# That line of input is `import test`.
test()