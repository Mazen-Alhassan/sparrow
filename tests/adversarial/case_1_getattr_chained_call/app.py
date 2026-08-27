import vuln

def main():
    name = "ba" + "d"
    getattr(vuln, name)()

if __name__ == "__main__":
    main()
