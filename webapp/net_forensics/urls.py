from django.conf.urls import url
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^analyse', views.analyse, name='analyse')
]

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
