# Create your tasks here

from celery import shared_task
from celery_progress.backend import ProgressRecorder
from django.contrib.sessions.backends.db import SessionStore
from django.urls import reverse
from .models import *
from .scripts.regex_ip import *

import requests
import nmap
import time
import sublist3r
import dns.name
import dns.resolver

def compare_list(list_ban, list_base, list_delta, list_subdomains, list_ip_entry, scan_db):

	# Obtenir la différence entre la liste de sous-domaine du scan et la concatenation de la liste de référence et la liste d'exclusion et la liste de delta
	list_diff = list(list_ban) + list(list_base) + list(list_delta)
	list_delta_sub_to_db = list(set(list_subdomains) - set(list_diff))
	list_delta_ip_to_db = list(set(list_ip_entry) - set(list_diff))

	# Ajouter sous-domaines non-présent dans les listes de références, d'exclusion et de delta dans la liste de delta
	for delta in list_delta_sub_to_db:
		asset = Asset(scan=scan_db, name_asset=delta, data_type='subdom', list_status='delta')
		asset.save()
		log = Log(asset=asset, list_from='none', list_to='delta')
		log.save()


	# Ajouter IP non-présent dans les listes de références, d'exclusion et de delta dans la liste de delta
	for delta in list_delta_ip_to_db:
		asset = Asset(scan=scan_db, name_asset=delta, data_type='ip', list_status='delta')
		asset.save()
		log = Log(asset=asset, list_from='none', list_to='delta')
		log.save()


def dig_scan(subdomain):
    publicIP_list = []
    try:
        n = dns.name.from_text(subdomain)
        answer = dns.resolver.resolve(n,'A')
        for rdata in answer:
            publicIP_list.append(rdata.to_text())
        return publicIP_list
    except:
        pass


def sublist3r_scan(domain, is_bruteforced):
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=is_bruteforced, engines=None)

    return subdomains


@shared_task(bind=True)
def run_sublist3r_scan(self, list_domains, is_bruteforced = True, list_ban = None, list_base = None, list_base_ip = None, list_delta = None, scan_id = None):
	#Instanciation de la barre de progression
	progress_recorder = ProgressRecorder(self)

	list_subdomains = []
	list_ip_entry = []

	for index, domain in enumerate(list_domains):
		# Check si la ligne n'est pas une IPv4 ou IPv6
		if ipv4_address.match(domain) == None and ipv6_address.match(domain) == None:
			list_subdomains.extend(sublist3r_scan(domain, is_bruteforced))

		else:
			list_ip_entry.append(domain)

		progress_recorder.set_progress(index + 1, len(list_domains), description='Sublist3r en cours')

	# Ajout des données dans la base si ce n'est pas une recherche rapide
	if scan_id != None :
		#On recupére l'objet scan (de la BDD) depuis son ID
		new_scan = Scan.objects.get(pk=scan_id)

		# Comparer les sous-domaines trouvés et les IP d'entrées avec les trois listes et ajouter les différences dans la liste delta
		compare_list(list_ban, list_base + list_base_ip, list_delta, list_subdomains, list_ip_entry, new_scan)
	else :
		# Delete previous subdomains from database
		Temp_subdomains.objects.all().delete()

		public_IP = []
		for subdomain in list_subdomains:
			public_IP = dig_scan(subdomain)

			if isinstance(public_IP, list):
				public_IP = ' -- '.join(public_IP)

			# Save the subdomains in a temporary database
			temp_subdomains = Temp_subdomains(name=subdomain, ip=public_IP)
			temp_subdomains.save()

	return "Sublist3r effectué avec succès"

def callback_result(host, scan_result, last_scan, session_key, progress_recorder):
	# Augmenter la valeur de CONN_MAX_AGE dans settings.py si une erreur est levée
	session_callback = SessionStore(session_key=session_key)
	
	try :
		ports = scan_result['scan'][host]['tcp'].keys()
	
		for port in ports:
			protocol = scan_result['scan'][host]['tcp'][port]['name']

			# Creation d'un object Port uniquement s'il n'existe pas un port similaire dans la BDD
			Port.objects.get_or_create(protocol=protocol, num=int(port), scan=last_scan)

	except Exception as e :
		pass

	session_callback['current_callback'] += 1
	session_callback.save()

	progress_recorder.set_progress(session_callback['current_callback'], session_callback['total_callback'], description='Nmap en cours')


@shared_task(bind=True)
def run_nmap_scan(self, publicIP_list, scan_id):
	progress_recorder = ProgressRecorder(self)
	last_scan = Scan.objects.get(pk=scan_id)

	nma = nmap.PortScannerAsync()

	session_callback = SessionStore()
	session_callback['current_callback'] = 0
	session_callback['total_callback'] = len(publicIP_list)
	session_callback.create()
	session_key_callback = session_callback.session_key

	for publicIP in publicIP_list :
		time.sleep(2)
		nma.scan(hosts=publicIP, arguments='-p- --open -Pn', callback=callback_result, scan_id=last_scan, session_key=session_key_callback, progress_recorder=progress_recorder)

	session_callback_finish = SessionStore(session_key=session_key_callback)
	while session_callback_finish['current_callback'] != session_callback_finish['total_callback']:
		time.sleep(5)
		session_callback_finish = SessionStore(session_key=session_key_callback)

	return "NMAP effectué avec succès"