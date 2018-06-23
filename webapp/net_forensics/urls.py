from django.conf.urls import url
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^analyse', views.analyse, name='analyse'),
    url(r'^arp', views.arp, name="arp"),
    url(r'^darknet', views.darknet, name="darknet"),
    url(r'^dhcp', views.dhcp, name="dhcp"),
    url(r'^dns', views.dns, name="dns"),
    url(r'^port_scanning', views.port_scanning, name="port_scanning"),
    url(r'^smtp', views.smtp, name="smtp")
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
