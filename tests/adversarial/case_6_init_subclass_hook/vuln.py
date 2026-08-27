def bad():
    print("SINK EXECUTED")

class Base:
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        bad()
