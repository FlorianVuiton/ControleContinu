# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.template import loader
from django.http import HttpResponse
from django import template

from .forms import QuickSearchForm

import sublist3r
import dns.name
import dns.resolver

import subprocess


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
            domain = form.cleaned_data['domain']
            subdomains = sublist3r_scan(domain)

            quick_search_dict = {}

            for subdomain in subdomains:
                quick_search_dict[subdomain] = dig_scan(subdomain)

            print(quick_search_dict)
            
            context =  {'form'  : form,
                'quick_search_dict'    : quick_search_dict.items(),
            }
            
        else:
            # Form data doesn't match the expected format.
            context['errors'] = form.errors.items()
    else:
        form = QuickSearchForm()
        context =   {'form' : form}
    
    html_template = loader.get_template('quick_search.html')

    return HttpResponse(html_template.render(context, request))
    #return render(request, 'quick_search.html', context)


def sublist3r_scan(domain):
    #Use os.path pour le chemin absolue
    #pout = subprocess.Popen(["/home/florian/Documents/ControleContinu/app/script/sublist3r/sublist3r.py", "-d", domain, "-o script/sublist3r/sub", ], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #pout.wait()
    
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=False, verbose=False, enable_bruteforce=False, engines=None)

    #print(subdomains)
    return subdomains
    """
    pout.wait()


    rslt, err = pout.communicate()
    print(rslt)
    print("###################################################################################")
    print(err)
    """

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