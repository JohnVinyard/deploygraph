class Colors(object):

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def ok(msg):
        print(Colors.OKBLUE + msg + Colors.ENDC)

    @staticmethod
    def success(msg):
        print(Colors.OKGREEN + msg + Colors.ENDC)

    @staticmethod
    def bad(msg):
        print(Colors.FAIL + msg + Colors.ENDC)

    @staticmethod
    def format(msg, code):
        return code + msg + Colors.ENDC
