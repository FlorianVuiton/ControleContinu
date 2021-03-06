# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Client(models.Model):
	id_client 			= models.AutoField(primary_key=True)
	name_client			= models.CharField(max_length=100)
	description			= models.CharField(max_length=500, blank=True)
	logoname 			= models.CharField(max_length=100, blank=True)

	def __str__(self):
		return self.name_client


class Scan(models.Model):
	id_scan 			= models.AutoField(primary_key=True)
	date 				= models.DateField(auto_now_add=True)
	client 				= models.ForeignKey(Client, on_delete=models.CASCADE)

	def __str__(self):
		return str(self.id_scan)


class Asset(models.Model):
	DATA_TYPE_CHOICE 	= [
		('ip', 'publicIP'),
		('subdom', 'subdomain'),
	]

	LIST_STATUS_CHOICE	= [
		('none', 'none'),
		('base', 'base_list'),
		('ban', 'ban_list'),
		('delta', 'delta_list'),
	]
	id_asset 			= models.AutoField(primary_key=True)
	scan 				= models.ForeignKey(Scan, on_delete=models.CASCADE)
	name_asset			= models.CharField(max_length=100)
	data_type			= models.CharField(max_length=6, choices=DATA_TYPE_CHOICE)
	list_status			= models.CharField(max_length=5, choices=LIST_STATUS_CHOICE)

	def __str__(self):
		return self.name_asset


class Port(models.Model):
	id_port 			= models.AutoField(primary_key=True)
	num					= models.IntegerField()
	protocol			= models.CharField(max_length=100)
	scan 				= models.ForeignKey(Scan, on_delete=models.CASCADE)

	def __str__(self):
		return self.protocol

class Log(models.Model):
	LIST_CHOICE	= [
		('none', 'none'),
		('base', 'base_list'),
		('ban', 'ban_list'),
		('delta', 'delta_list'),
	]
	id_log 				= models.AutoField(primary_key=True)
	asset 				= models.ForeignKey(Asset, on_delete=models.CASCADE)
	list_from			= models.CharField(max_length=5, choices=LIST_CHOICE)
	list_to 			= models.CharField(max_length=5, choices=LIST_CHOICE)
	date 				= models.DateField(auto_now=True)

class Temp_subdomains(models.Model):
	id_temp_subdomains 	= models.AutoField(primary_key=True)
	name				= models.CharField(max_length=100)
	ip 					= models.CharField(max_length=100, null=True, blank=True)

	def __str__(self):
		return self.name
		
