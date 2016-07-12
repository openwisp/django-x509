import sys


def bytes_compat(string, encoding='utf8'):
    if sys.version_info.major >= 3:
        return bytes(string, encoding)
    else:
        return bytes(string)
