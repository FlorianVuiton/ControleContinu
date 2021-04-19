# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path, re_path
from app import views

urlpatterns = [

    # The home page
    path('', views.index, name='home'),    

    path('quick_search.html/', views.quick_search, name='quick_search'),

    # Matches any html file
    re_path(r'^.*\.*', views.pages, name='pages'),

]
