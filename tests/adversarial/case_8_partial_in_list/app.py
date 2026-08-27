import functools
import vuln

def main():
    name = "ba" + "d"
    tasks = [functools.partial(getattr(vuln, name))]
    i = len(tasks) - 1
    tasks[i]()

if __name__ == "__main__":
    main()
