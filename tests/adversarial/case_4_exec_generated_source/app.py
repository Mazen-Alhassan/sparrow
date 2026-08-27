def main():
    code = "from vuln import bad\nbad()\n"
    exec(code)

if __name__ == "__main__":
    main()
