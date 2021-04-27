# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.template import loader
from django.http import HttpResponse
from django import template
from django.db.models import Q
from django.template.response import TemplateResponse

from .forms import *
from .models import *

import sublist3r
import dns.name
import dns.resolver
import nmap
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
    
    except:
        pass
    """
    except template.TemplateDoesNotExist:

        html_template = loader.get_template( 'page-404.html' )
        return HttpResponse(html_template.render(context, request))

    except:
    
        html_template = loader.get_template( 'page-500.html' )
        return HttpResponse(html_template.render(context, request))
    """

@login_required(login_url="/login/")
def quick_search(request):
    context = {}
    
    if request.method == 'POST':
        form = QuickSearchForm(request.POST)
        if form.is_valid():
            domains = form.cleaned_data['domain']
            list_domains = domains.split(", ")

            list_subdomains = []
            # for domain in list_domains:
            #     list_subdomains.append(sublist3r_scan(domain))

            for domain in list_domains:
                list_subdomains.extend(sublist3r_scan(domain))

            #print(list_subdomains)
            #subdomains = sublist3r_scan(domains)

            quick_search_dict = {}
            for subdomain in list_subdomains:
                quick_search_dict[subdomain] = dig_scan(subdomain)


            # if not subdomains :
            #     #TODO display error message
            #     pass

            # for i, subdomains in enumerate(list_subdomains):
            #     for subdomain in subdomains:
            #         quick_search_dict_temp+i = {}
            #         print(quick_search_dict_temp+i)
            #         quick_search_dict_temp+i = [subdomain] = dig_scan(subdomain)
            # print(quick_search_dict_temp1)
            # print('############################')
            # print(quick_search_dict_temp2)

            # for subdomains in list_subdomains:
            #     for subdomain in subdomains:
            #         print()
            #         quick_search_dict_temp[subdomain] = dig_scan(subdomain)

            # print(quick_search_dict_temp)
            # #print(quick_search_dict_temp)

            # quick_search_dict = {}
            # for key, ele in zip(list_domains, quick_search_dict_temp.items()):
            #     quick_search_dict[key] = dict([ele])

            # print(quick_search_dict)


            context =  {
                'form'  : form,
                'quick_search_dict'    : quick_search_dict.items(),
                'segment' : 'quick_search',
            }
            
        else:
            # Form data doesn't match the expected format.
            context['errors'] = form.errors.items()
    else:
        form = QuickSearchForm()
        context =   {
            'form' : form,
            'segment' : 'quick_search',
        }
    
    html_template = loader.get_template('quick_search.html')

    return HttpResponse(html_template.render(context, request))

def sublist3r_scan(domain):
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)

    return subdomains


def dig_scan(subdomain):

    publicIP_list = []

    try:

        n = dns.name.from_text(subdomain)
        answer = dns.resolver.query(n,'A')

        for rdata in answer:
            publicIP_list.append(rdata.to_text())

        return publicIP_list

    except:
        pass

@login_required(login_url="/login/")
def show_client(request):
    context = {}

    clients = Client.objects.all()
    context = {
        'clients' : clients,
        'segment' : 'show_client',
    }

    html_template = loader.get_template('client.html')

    return HttpResponse(html_template.render(context, request))

def callback_result(host, scan_result, last_scan):
    # Augmenter la valeur de CONN_MAX_AGE dans settings.py si une erreur est levée

    ports = scan_result['scan'][host]['tcp'].keys()

    for port in ports:
        protocol = scan_result['scan'][host]['tcp'][port]['name']

        # Creation d'un object Port uniquement s'il n'existe pas un port similaire dans la BDD
        Port.objects.get_or_create(protocol=protocol, num=int(port), scan=last_scan)


def show_controle_continu(request):
    context = {}

    list_ban = []
    list_base = []
    list_base_ip = []
    list_delta = []
    list_port = []

    if 'client_id' in request.POST:
        client_id = request.POST.get("client_id", "")
        request.session['client_id'] = client_id
        form = SearchForm()
    else:
        client_id = request.session.get('client_id')

    if 'to_list_base' in request.POST:
        form = SearchForm()
        asset_delta = request.POST.get("to_list_base", "")
        asset_base = Asset.objects.filter(scan__client_id=client_id).get(name_asset=asset_delta)
        asset_base.list_status = 'base'
        asset_base.save()
        log = Log(asset=asset_base, list_from='delta', list_to='base')
        log.save()

    if 'to_list_ban' in request.POST:
        form = SearchForm()
        asset_delta = request.POST.get("to_list_ban", "")
        asset_ban = Asset.objects.filter(scan__client_id=client_id).get(name_asset=asset_delta)
        asset_ban.list_status = 'ban'
        asset_ban.save()
        log = Log(asset=asset_ban, list_from='delta', list_to='ban')
        log.save()

    # Requête SQL de la liste d'exclusion:
    # SELECT * FROM `app_asset` INNER JOIN `app_scan` ON (`app_asset`.`scan_id` = `app_scan`.`id_scan`) WHERE (`app_asset`.`data_type` = subdom AND `app_asset`.`list_status` = ban AND `app_scan`.`client_id` = client_id)
    list_ban_queryset = Asset.objects.filter(data_type='subdom', list_status='ban', scan__client_id=client_id)
    
    # Requête SQL de la liste de référence:
    # SELECT * FROM `app_asset` INNER JOIN `app_scan` ON (`app_asset`.`scan_id` = `app_scan`.`id_scan`) WHERE ((`app_asset`.`data_type` = subdom OR `app_asset`.`data_type` = ip) AND `app_asset`.`list_status` = base AND `app_scan`.`client_id` = 1)
    list_base_queryset = Asset.objects.filter(Q(data_type='subdom') | Q(data_type='ip'), list_status='base', scan__client_id=client_id)

    # Requête SQL de la liste de delta:
    # SELECT * FROM `app_asset` INNER JOIN `app_scan` ON (`app_asset`.`scan_id` = `app_scan`.`id_scan`) WHERE (`app_asset`.`data_type` = subdom AND `app_asset`.`list_status` = delta AND `app_scan`.`client_id` = client_id)
    list_delta_queryset = Asset.objects.filter(data_type='subdom', list_status='delta', scan__client_id=client_id)

    #Requête SQL de la liste de port:
    list_port_queryset = Port.objects.filter(scan__client_id=client_id)

    # Requete SQL sur la table Scan
    scan_queryset = Scan.objects.filter(client_id=client_id)

    # Recherche du client en fonction de son id
    client = Client.objects.get(id_client=client_id)

    # list_queryset = Asset.objects.filter(data_type='subdom', scan__client_id=client_id)
    # for asset in list_queryset:
    #     if asset.list_status == 'ban':
    #         list_ban.append(asset.name_asset)

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
        form = QuickSearchForm()
        # Faire un dig pour tous les sous-domaines
        publicIP_list_from_dig = []
        for base in list_base:
#Faire un test si publicIP = None car pas d'addresse d'IP !!!!!!!!!!!!!
            publicIP_list_from_dig += dig_scan(base)
            # Enlever tous les doublons
            publicIP_list_from_dig = list(set(publicIP_list_from_dig))

        print('###################')
        print('Dig terminé')
        print('###################')
        
        # Rechercher toutes addresses publiques dans Asset avec le list_status = ip
        # publicIP_list_from_db = Asset.objects.filter(data_type='ip', list_status='base', scan__client_id=client_id).values_list('name_asset', flat=True)

        # Concatenation de la liste issue du dig et la liste d'ip dans la liste de référence
        publicIP_list = publicIP_list_from_dig + list_base_ip

        nma = nmap.PortScannerAsync()

        print('###################')
        print(publicIP_list)
        print('###################')

        #publicIP_list.append('2555.2225.2555.255')
        # On ajoute un dernier élément dans la liste car la fonction ne renvoie jamais le dernier callback
        publicIP_list.append('dernier élément non lu')

        # Recherche le dernier scan effectué
        last_scan = Scan.objects.filter(client=client_id).last()

        for publicIP in publicIP_list:
            nma.scan(hosts=publicIP, arguments='-Pn -p22-443 --open', callback=callback_result, scan_id=last_scan)
            #nma.scan(hosts=publicIP, arguments='-p- --open -T 2', callback=callback_result)

        # while nma.still_scanning():
        #     # print("Waiting >>>")
        #     nma.wait(10)

        # for publicIP in publicIP_list:
        #     print(nma[publicIP]['tcp'].keys())


    if 'sublist3r' in request.POST:
        #form = SearchForm(request.POST, request.FILES)
        #if form.is_valid():
        if 'file_domain' in request.FILES:
            file = request.FILES['file_domain']
            list_domains = file.readlines()
            
            list_subdomains = []
            for domain in list_domains:
                list_subdomains.extend(sublist3r_scan(domain.decode().replace('\r', '').replace('\n', '')))
            # domains = form.cleaned_data['domain']
            # list_domains = domains.split(" ")

            # list_subdomains = []
            # for domain in list_domains:
            #     list_subdomains.extend(sublist3r_scan(domain))
            print('###################')
            print('Sublist3r terminé')
            print('###################')

            # Ajouter un champs dans la table Scan
            scan_db = Scan(client=client)
            scan_db.save()

            # Comparer les sous-domaines trouvés et ajouter les différences dans la liste delta
            compare_list(list_ban, list_base, list_delta, list_subdomains, scan_db)
            # Puis recharger les nouvelles valeurs (ou pas) de la liste delta
            list_delta_queryset = Asset.objects.filter(data_type='subdom', list_status='delta', scan__client_id=client_id)

    if 'download_file_delta' in request.POST:
        form = SearchForm()
        return download_file(list_delta, 'liste_de_delta.csv')
    elif 'download_file_subdomain' in request.POST:
        form = SearchForm()
        return download_file(list_base + list_base_ip, 'liste_de_sous_domaine.csv')
    elif 'download_file_port' in request.POST:
        form = SearchForm()

        return download_file(list_port, 'liste_de_port.csv')

            
    context =   {
        #'form'          : form,
        'client'        : client,
        'list_ban'      : list_ban_queryset,
        'list_base'     : list_base_queryset,
        'list_delta'    : list_delta_queryset,
        'list_port'     : list_port_queryset,
        'scan_history'  : scan_queryset,
        'segment'       : 'show_client',
    }


    html_template = loader.get_template('controlecontinu.html')

    return HttpResponse(html_template.render(context, request))


def compare_list(list_ban, list_base, list_delta, list_subdomains, scan_db):

    # Obtenir la différence entre la liste de sous-domaine du scan et la concatenation de la liste de référence et la liste d'exclusion et la liste de delta
    list_diff = list(list_ban) + list(list_base) + list(list_delta)
    list_delta = list(set(list_subdomains) - set(list_diff))

    # Ajouter le(s) asset(s) non-présent dans les listes de références et d'exclusion dans la liste de delta
    for delta in list_delta:
        asset = Asset(scan=scan_db, name_asset=delta, data_type='subdom', list_status='delta')
        asset.save()
        log = Log(asset=asset, list_from='none', list_to='delta')
        log.save()


def download_file(list_to_download, file_name):

    list_to_string = ""
    for line in list_to_download:
        list_to_string += str(line) + '\r\n'

    buffer = io.StringIO(list_to_string)
    reader = csv.reader(buffer, skipinitialspace=True)

    buffer = io.StringIO() 
    wr = csv.writer(buffer, lineterminator='\r\n',)
    wr.writerows(reader)

    buffer.seek(0)
    response = HttpResponse(buffer, content_type='text/csv')

    response['Content-Disposition'] = 'attachment; filename='+file_name

    return response


"""
Importer fichier de domain
Empecher le téléchargement des fichiers csv si : ils sont vide, le nmap n'est pas fini
Message d'erreur si le dig ou nmap ne renvoie rien
Possibilité d'ajouter des IP et sous domaines dans la liste de domaine d'entrée
"""

# AJOUTER UN STATUS À SCAN POUR SAVOIR SI LE NMAP EST FINI

