"""
URL configuration for shopymes project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.conf import settings
from django.urls import path, re_path
from django.views.static import serve
from app.models import Configuration
from app import views
from app.tasks import PeriodicMonitorizationFunction

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home),
    path('login', views.login_user),
    path('logout', views.logut_user),
    path('scans/', views.scans),
    path('scans/create', views.add_scan),
    path('scans/<int:host_id>', views.details_scan),
    path('scans/<int:host_id>/raw', views.details_scan_raw_data),
    path('scans/delete/<int:host_id>', views.delete_service_scan),
    path('vulnerabilities/',views.vulnerabilities),
    path('vulnerabilities/<str:vuln_str>', views.delete_vulnerability),
    path('monitorization/', views.monitorization),
    path('configuration', views.configuration),
    path('configuration/<str:tab>', views.configuration),
    path('exportar-csv-services/', views.exportar_csv_services),
    re_path(r'^media/(?P<path>.*)$', serve,{'document_root': settings.MEDIA_ROOT}), 
    re_path(r'^static/(?P<path>.*)$', serve,{'document_root': settings.STATIC_ROOT}), 
]

if len(Configuration.objects.all()) == 0:
    conf = Configuration(monitorization=False, ips_monitorization='')
    conf.save()

periodic = PeriodicMonitorizationFunction()
periodic.setDaemon(True)
periodic.start()