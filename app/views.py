# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.template import loader
from django.http import HttpResponse
from django.http import JsonResponse
from django import template
from django.db.models import Q
from django.template.response import TemplateResponse
from django.core import serializers
from django.contrib.sessions.models import Session

from celery import current_app 

from .forms import *
from .tasks import *

import csv, io

@login_required(login_url="/login/")
def index(request):
	
	context = {}
	context['segment'] = 'index'

	html_template = loader.get_template( 'index.html' )
	return HttpResponse(html_template.render(context, request))

@login_required(login_url="/login/")
def pages(request):
	context = {}
	# All resource paths end in .html.
	# Pick out the html file name from the url. And load that template.
	try:
		
		load_template      = request.path.split('/')[-1]
		context['segment'] = load_template
		
		html_template = loader.get_template( load_template )
		return HttpResponse(html_template.render(context, request))

	except template.TemplateDoesNotExist:

		html_template = loader.get_template( 'page-404.html' )
		return HttpResponse(html_template.render(context, request))

	except:
	
		html_template = loader.get_template( 'page-500.html' )
		return HttpResponse(html_template.render(context, request))

@login_required(login_url="/login/")
def quick_search(request):
	context = {}
	
	if request.method == 'POST':
		form = QuickSearchForm(request.POST)
		if form.is_valid():
			domains = form.cleaned_data['domain']
			list_domains = domains.split(", ")

			bruteforce = False
			# Bruterforcer les domaines
			if request.POST.get('bruteforce', False) :
				bruteforce = True

			# Lancement de sublist3r dans une task asynchrone
			result = run_sublist3r_scan.delay(list_domains, bruteforce)

			context =  {
				'form'  : form,
				'segment' : 'quick_search',
				'task_id': result.task_id,
			}	
		else:
			# Form data doesn't match the expected format.
			context['errors'] = form.errors.items()
	else:
		form = QuickSearchForm()
		context =   {
			'form' 		: form,
			'segment' 	: 'quick_search',
		}
	
	html_template = loader.get_template('quick_search.html')

	return HttpResponse(html_template.render(context, request))


@login_required(login_url="/login/")
def show_client(request):
	context = {}

	if request.method == 'POST':
		form = CreateClientForm(request.POST)
		if form.is_valid():
			client_name = form.cleaned_data['name']
			client_description = form.cleaned_data['description']
			client_logoname= form.cleaned_data['logoname']
			
			# Sauvegarder le client dans la BDD
			client = Client(name_client=client_name, description=client_description, logoname=client_logoname)
			client.save()        
		else :
			# Form data doesn't match the expected format.
			context['errors'] = form.errors.items()
	else :
		form = CreateClientForm()

	clients = Client.objects.all()
	context = {
		'form'      : form,
		'clients'   : clients,
		'segment'   : 'show_client',
	}

	html_template = loader.get_template('client.html')

	return HttpResponse(html_template.render(context, request))

@login_required(login_url="/login/")
def show_controle_continu(request):
	context = {}

	list_ban = []
	list_base = []
	list_base_ip = []
	list_delta = []
	list_port = []

	info_to_display = ""
	task_id = ""

	if 'client_id' in request.POST:
		client_id = request.POST.get("client_id", "")
		request.session['client_id'] = client_id
	else:
		client_id = request.session.get('client_id')

	if 'to_list_base' in request.POST:
		id_asset = request.POST.get("to_list_base", "")
		change_asset_list(id_asset, 'ban', 'base', client_id)

	if 'to_list_ban' in request.POST:
		id_asset = request.POST.get("to_list_ban", "")
		change_asset_list(id_asset, 'base', 'ban', client_id)

	if 'change_list' in request.POST:
		for key, value in request.POST.items():
			if value != 'over':
				id_asset = key.replace('radio_', '')
				if value == 'to_base':
					change_asset_list(id_asset, 'delta', 'base', client_id)
				elif value == 'to_ban':
					change_asset_list(id_asset, 'delta', 'ban', client_id)
			else:
				break


	# Requête SQL de la liste d'exclusion:
	# SELECT * FROM `app_asset` INNER JOIN `app_scan` ON (`app_asset`.`scan_id` = `app_scan`.`id_scan`) WHERE (`app_asset`.`data_type` = subdom AND `app_asset`.`list_status` = ban AND `app_scan`.`client_id` = client_id)
	list_ban_queryset = Asset.objects.filter(Q(data_type='subdom') | Q(data_type='ip'), list_status='ban', scan__client_id=client_id).order_by('-data_type', 'name_asset')
	
	# Requête SQL de la liste de référence:
	# SELECT * FROM `app_asset` INNER JOIN `app_scan` ON (`app_asset`.`scan_id` = `app_scan`.`id_scan`) WHERE ((`app_asset`.`data_type` = subdom OR `app_asset`.`data_type` = ip) AND `app_asset`.`list_status` = base AND `app_scan`.`client_id` = 1)
	list_base_queryset = Asset.objects.filter(Q(data_type='subdom') | Q(data_type='ip'), list_status='base', scan__client_id=client_id).order_by('-data_type', 'name_asset')

	# Requête SQL de la liste de delta:
	# SELECT * FROM `app_asset` INNER JOIN `app_scan` ON (`app_asset`.`scan_id` = `app_scan`.`id_scan`) WHERE (`app_asset`.`data_type` = subdom AND `app_asset`.`list_status` = delta AND `app_scan`.`client_id` = client_id)
	list_delta_queryset = Asset.objects.filter(Q(data_type='subdom') | Q(data_type='ip'), list_status='delta', scan__client_id=client_id).order_by('-data_type', 'name_asset')

	# Recherche le dernier scan effectué
	last_scan = Scan.objects.filter(client=client_id).last()

	#Requête SQL de la liste de port du dernier scan:
	list_port_queryset = Port.objects.filter(scan__client_id=client_id, scan=last_scan).order_by('num')

	# Requete SQL sur la table Scan
	scan_queryset = Scan.objects.filter(client_id=client_id).order_by('-id_scan')

	# Recherche du client en fonction de son id
	client = Client.objects.get(id_client=client_id)

	for ban in list_ban_queryset:
		list_ban.append(ban.name_asset)
	for base in list_base_queryset:
		if base.data_type == 'subdom':
			list_base.append(base.name_asset)
		if base.data_type == 'ip':
			list_base_ip.append(base.name_asset)
	for delta in list_delta_queryset:
		list_delta.append(delta.name_asset)
	for port in list_port_queryset:
		list_port.append(port.num)

	if 'dig_nmap' in request.POST:
		# Faire un dig pour tous les sous-domaines
		publicIP_list_from_dig = []
		for base in list_base:
#Faire un test si publicIP = None car pas d'addresse d'IP !!!!!!!!!!!!!
			dig_ip = dig_scan(base)

			if (dig_ip != None):
				publicIP_list_from_dig += dig_ip

		# Enlever tous les doublons
		publicIP_list_from_dig = list(set(publicIP_list_from_dig))

		# Concatenation de la liste issue du dig et la liste d'ip dans la liste de référence
		publicIP_list = publicIP_list_from_dig + list_base_ip

		# On enleve les doublons
		publicIP_list = list(set(publicIP_list))

		# Lancement de nmap dans une task asynchrone
		result_nmap = run_nmap_scan.delay(publicIP_list, last_scan.id_scan)

		info_to_display = "Nmap en cours sur "+ str(len(publicIP_list)) +" IPs : " + ' -- '.join(str(IP) for IP in publicIP_list)
		
		list_port_queryset = Port.objects.filter(scan__client_id=client_id, scan=last_scan)

	if 'sublist3r' in request.POST:
		if 'file_domain' in request.FILES:
			file = request.FILES['file_domain']
			file_lines = file.readlines()

			# Ajouter un champs dans la table Scan
			scan_db = Scan(client=client)
			scan_db.save()
			list_domains = []
			bruteforce = False

			for line in file_lines:
				# Convertir bytes-like object into string
				list_domains.append(line.decode().replace('\r', '').replace('\n', ''))

			# Bruterforcer les domaines
			if request.POST.get('bruteforce', False) :
				bruteforce = True
			
			# Lancement de sublist3r dans une task asynchrone
			result_sublist3r = run_sublist3r_scan.delay(list_domains, bruteforce, list_ban, list_base, list_base_ip, list_delta, scan_db.id_scan)

			info_to_display = "Sublist3r en cours sur "+ str(len(list_domains)) +" domaines : " + ' -- '.join(str(domaine) for domaine in list_domains)

			# Puis recharger les nouvelles valeurs (ou pas) de la liste delta
			list_delta_queryset = Asset.objects.filter(Q(data_type='subdom') | Q(data_type='ip'), list_status='delta', scan__client_id=client_id)

	if 'download_file_delta' in request.POST:
		return download_file(list_delta, 'liste_de_delta.csv')
	elif 'download_file_subdomain' in request.POST:
		return download_file(list_base + list_base_ip, 'liste_référentielle.csv')
	elif 'download_file_port' in request.POST:
		# Convertir la liste de int en liste de port
		return download_file(map(str, list_port), 'liste_de_port.csv')

	# Check if a task is active
	tasks_is_active = current_app.control.inspect().active()
	if bool(tasks_is_active):
		for worker, tasks in list(tasks_is_active.items()):
			if tasks:
				# Get id of the active task for the progress bar
				task_id = ''.join((t['id']) for t in tasks)
			else:
				task_id = ""


	context =   {
		'client'                : client,
		'list_ban'              : list_ban_queryset,
		'list_base'             : list_base_queryset,
		'list_delta'            : list_delta_queryset,
		'list_port'             : list_port_queryset,
		'scan_history'          : scan_queryset,
		'segment'               : 'show_client',
		'information'			: info_to_display,
		'task_id'				: task_id
	}

	html_template = loader.get_template('controlecontinu.html')

	return HttpResponse(html_template.render(context, request))

def change_asset_list(id_asset, list_from, list_to, client_id):
	asset = Asset.objects.filter(scan__client_id=client_id).get(id_asset=id_asset)
	asset.list_status = list_to
	asset.save()
	log = Log(asset=asset, list_from=list_from, list_to=list_to)
	log.save()


def get_assets(request):
	# Request from controlecontinu
	if request.method == 'POST':
		if 'client_id' in request.POST:

			client_id = request.POST.get("client_id")

			assets = Asset.objects.filter(scan__client_id=client_id).order_by('data_type', '-name_asset')
			json_assets = serializers.serialize('json', assets)

			return JsonResponse(json_assets, safe=False)
	# Request from quick search
	else :
		temp_subdomains = Temp_subdomains.objects.all()
		json_subdomains = serializers.serialize('json', temp_subdomains)

		return JsonResponse(json_subdomains, safe=False)

def get_ports(request):
	# Request from controlecontinu
	if request.method == 'POST':
		if 'client_id' in request.POST:

			client_id = request.POST.get("client_id")
			last_scan = Scan.objects.filter(client=client_id).last()

			ports = Port.objects.filter(scan__client_id=client_id, scan=last_scan).order_by('-num')
			json_ports = serializers.serialize('json', ports)

			return JsonResponse(json_ports, safe=False)
	else :
		return JsonResponse(None)

def get_scans(request):
	# Request from controlecontinu
	if request.method == 'POST':
		if 'client_id' in request.POST:

			client_id = request.POST.get("client_id")

			scan = Scan.objects.filter(client_id=client_id).order_by('id_scan')
			json_scan = serializers.serialize('json', scan)

			return JsonResponse(json_scan, safe=False)
	else :
		return JsonResponse(None)

	


def download_file(list_to_download, file_name):

    if 'port' in file_name:
        list_to_string = ",".join(list_to_download)
    else :
        list_to_string = "\r\n".join(list_to_download)

    buffer = io.StringIO(list_to_string)
    reader = csv.reader(buffer, skipinitialspace=True)

    buffer = io.StringIO() 
    wr = csv.writer(buffer,)
    wr.writerows(reader)

    buffer.seek(0)
    response = HttpResponse(buffer, content_type='text/csv')

    response['Content-Disposition'] = 'attachment; filename='+file_name

    return response


"""
Empecher le téléchargement des fichiers csv si : ils sont vide, le nmap n'est pas fini
Message d'erreur si le dig ou nmap ne renvoie rien
Réchargement tableau des ports
Ajouter les domaines du fichiers d'entrée du la BDD
Dans la lsite de téléchargement des sous-domaines, enlever les doublons IP assoscié au sous-domaine et sous-domaine

"""

# 1 : RADIO BUTTON POUR ACTIVER OU NON SUBRUTE (SUBLIST3R)
# 2 : SE RENSEIGNER SUR SUBBRUTE

