from django.dispatch import Signal

x509_renewed = Signal()
x509_renewed.__doc__ = """
Providing arguments: ['instance']
"""
