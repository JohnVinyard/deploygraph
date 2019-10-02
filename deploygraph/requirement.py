from .colors import Colors
import time


class AlwaysUpdateException(Exception):
    pass


def retry(tries, delay):
    def decorator(f):
        def x(*args, **kwargs):
            for i in range(tries):
                try:
                    return f(*args, **kwargs)
                except:
                    instance = args[0]
                    cls = instance.__class__.__name__
                    func_name = f.__name__
                    Colors.bad(
                        'try {i} of {tries} failed for {cls}.{func_name}()'
                            .format(**locals()))
                    if i == tries - 1:
                        raise
                    else:
                        time.sleep(delay)

        return x

    return decorator


class Requirement(object):
    def __init__(self, *dependencies):
        super(Requirement, self).__init__()
        self.dependencies = dependencies

    def fulfilled(self):
        raise NotImplementedError()

    def fulfill(self):
        raise NotImplementedError()

    def data(self):
        raise NotImplementedError()

    def _check_n(self, n, delay=1):
        for _ in range(n):
            if self.fulfilled():
                return True
            time.sleep(delay)
        return False

    def __call__(self):

        for dependency in self.dependencies:
            # TODO: remove this None check. this is just for development
            if dependency is not None:
                dependency()

        try:
            if self.fulfilled():
                Colors.ok('Requirement {cls} already fulfilled!'.format(
                    cls=self.__class__.__name__))
                return
        except AlwaysUpdateException:
            # this requirement should always re-run
            pass

        self.fulfill()

        try:
            if not self._check_n(10, delay=1):
                msg = 'Requirement {cls} not fulfilled after operation'
                raise RuntimeError(
                    (Colors.FAIL + msg + Colors.ENDC)
                        .format(cls=self.__class__.__name__))
        except AlwaysUpdateException:
            pass

        Colors.success(
            'Requirement {cls} fulfilled after operation'
                .format(cls=self.__class__.__name__))
