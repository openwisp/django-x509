import sys

import six


def bytes_compat(string, encoding='utf8'):
    if sys.version_info.major >= 3:
        if not isinstance(string, six.string_types):
            string = str(string)
        return bytes(string, encoding)
    else:
        return bytes(string)
