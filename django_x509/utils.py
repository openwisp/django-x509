def bytes_compat(string, encoding='utf8'):
    if not isinstance(string, str):
        string = str(string)
    return bytes(string, encoding)
