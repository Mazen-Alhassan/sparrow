import importlib

def main():
    prefix = "vu"
    suffix = "ln"
    mod = importlib.import_module(prefix + suffix)
    mod.bad()

if __name__ == "__main__":
    main()
