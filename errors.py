class Error(Exception):
    pass

class DBerror(Error):
    pass

class InvalidArgumentError(Error):
    pass

class UserError(Error):
    pass