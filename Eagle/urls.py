"""MoguScan URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf.urls import include, url
from django.contrib import admin
from django.views.generic.base import RedirectView
import settings

urlpatterns = [
    url(r'^$', 'xunhang.views.index', name='index'),
    url(r'^config/$', 'xunhang.views.config', name='config'),
    url(r'^engine_start_main/$', 'xunhang.views.engine_start_main', name='engine_start_main'),
    url(r'^engine_stop_main/$', 'xunhang.views.engine_stop_main', name='engine_stop_main'),
    url(r'^result/$', 'xunhang.views.show_result', name='show_result'),
    url(r'^favicon\.ico$', RedirectView.as_view(url='/static/favicon.ico', permanent=True)),
    url(r'^admin/', include(admin.site.urls)),
]
