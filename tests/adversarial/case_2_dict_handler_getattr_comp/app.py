import vuln

NAMES = ["bad"]
HANDLERS = {n: getattr(vuln, n) for n in NAMES}

def main():
    key = NAMES[0]
    HANDLERS[key]()

if __name__ == "__main__":
    main()
