# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path, re_path, include
from app import views

urlpatterns = [

    # The home page
    path('', views.quick_search, name='home'),    

    path('quick_search.html/', views.quick_search, name='quick_search'),
    path('client.html/', views.show_client, name='show_client'),
    path('controlecontinu.html/', views.show_controle_continu, name='show_controle_continu'),
    path('get_assets/', views.get_assets, name="get_assets"),
    path('get_ports/', views.get_ports, name="get_ports"),
    path('get_scans/', views.get_scans, name="get_scans"),
    path('celery-progress/', include('celery_progress.urls')),

    # Matches any html file
    re_path(r'^.*\.*', views.pages, name='pages'),

]
