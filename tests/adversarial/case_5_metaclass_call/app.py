from vuln import bad

class Meta(type):
    def __call__(cls, *a, **kw):
        bad()
        return super().__call__(*a, **kw)

class Service(metaclass=Meta):
    def __init__(self):
        self.ready = True

def main():
    Service()

if __name__ == "__main__":
    main()
