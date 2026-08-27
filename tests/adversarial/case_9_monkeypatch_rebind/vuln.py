class Service:
    def handle(self):
        return "original"

def bad(*args, **kwargs):
    print("SINK EXECUTED")

Service.handle = bad
