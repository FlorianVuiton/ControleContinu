# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.contrib import admin

from .models import *

# Register your models here.

admin.site.register(Asset)
admin.site.register(Client)
admin.site.register(Scan)
admin.site.register(Port)
