# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path, re_path
from app import views

urlpatterns = [

    # The home page
    path('', views.quick_search, name='home'),    

    path('quick_search.html/', views.quick_search, name='quick_search'),
    path('client.html/', views.show_client, name='show_client'),
    path('controlecontinu.html/', views.show_controle_continu, name='show_controle_continu'),
    path('refresh_data/', views.refresh_data, name="refresh_data"),

    # Matches any html file
    #re_path(r'^.*\.*', views.pages, name='pages'),

]
