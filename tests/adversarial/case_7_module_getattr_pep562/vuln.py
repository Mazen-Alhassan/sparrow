def bad():
    print("SINK EXECUTED")

def __getattr__(name):
    if name == "trigger":
        return bad()
    raise AttributeError(name)
