from django.conf.urls import url

from . import views

app_name = 'x509'
urlpatterns = [
    url(r'^x509/ca/(?P<pk>[^/]+).crl$', views.crl, name='crl'),
]
