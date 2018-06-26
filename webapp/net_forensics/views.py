from django.shortcuts import render

# Create your views here.
import json
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage

from .helper import protocol_hierarchy_analysis
# from .helper import arp_analysis
from .helper import port_scanning_analysis
from .helper import smtp_analysis


def index(request):
    return render(request, 'index.html')


def analyse(request):
    if not request.method == 'POST':
        return index(request)
    try:
        myfile = request.FILES['capture_file']
    except:
        return index(request)
    fs = FileSystemStorage()
    filename = fs.save(myfile.name, myfile)
    uploaded_file_url = fs.url(filename)
    chart_dict = protocol_hierarchy_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'analyse.html', \
            {'uploaded_file_url': uploaded_file_url, \
             'uploaded_file_name': myfile.name, \
              'protocols_analysis_data_source': json.dumps(chart_dict) })


def arp(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    ip_mac_mappings = []
    # ip_mac_mappings = arp_analysis.main(uploaded_file_url.lstrip('/'))
    arp_data = {'ip_mac_mappings': ip_mac_mappings}
    return render(request, 'arp.html', arp_data)


def darknet(request):
    return render(request, 'darknet.html')


def dhcp(request):
    return render(request, 'dhcp.html')


def dns(request):
    return render(request, 'dns.html')

def dos(request):
    return render(request, 'dos.html')


def port_scanning(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    port_scanning_dicts = port_scanning_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'port_scanning.html', {'port_scanning_dicts': port_scanning_dicts})


def smtp(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    smtp_dissections = smtp_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'smtp.html', {'smtp_dissections': smtp_dissections})

def about(request):
    return render(request, 'about.html')
