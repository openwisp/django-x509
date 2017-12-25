from django.conf.urls import include, url
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

admin.autodiscover()


urlpatterns = [
    url(r'^admin/', admin.site.urls),
    # django-x509 urls
    # keep the namespace argument unchanged
    url(r'^', include('django_x509.urls', namespace='x509')),
]

urlpatterns += staticfiles_urlpatterns()
