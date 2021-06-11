# -*- encoding: utf-8 -*-
"""
python functions
"""

#import sublist3r
import dns.name
import dns.resolver
import csv, io

# def sublist3r_scan(domain):
#     subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)

#     return subdomains


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


def download_file(list_to_download, file_name):

    if 'port' in file_name:
        print(list_to_download)
        list_to_string = ",".join(list_to_download)
    else :
        print(list_to_download)
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