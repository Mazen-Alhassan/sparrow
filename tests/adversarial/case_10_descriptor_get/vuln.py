def bad():
    print("SINK EXECUTED")

class Trigger:
    def __get__(self, obj, owner):
        bad()
        return None

class Service:
    thing = Trigger()
