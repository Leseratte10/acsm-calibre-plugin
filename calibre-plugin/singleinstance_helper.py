from calibre.utils.lock import create_single_instance_mutex

class SingleInstance:

    def __init__(self, name):
        self.name = name
        self.release_mutex = None

    def __enter__(self):
        self.release_mutex = create_single_instance_mutex(self.name)
        return self.release_mutex is not None

    def __exit__(self, *a):
        if self.release_mutex is not None:
            self.release_mutex()
            self.release_mutex = None

