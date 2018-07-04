from django.shortcuts import render

# Create your views here.
import json
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage

from .helper import protocol_hierarchy_analysis
from .helper import arp_analysis
from .helper import port_scanning_analysis
from .helper import smtp_analysis
from .helper import dns_analysis
from .helper import darknet_analysis


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
    protocol_stats_data_source = protocol_hierarchy_analysis.chart_dict_to_stats(chart_dict)
    return render(request, 'analyse.html', \
            {'uploaded_file_url': uploaded_file_url, \
             'uploaded_file_name': myfile.name, \
              'protocols_analysis_data_source': json.dumps(chart_dict), \
              'protocol_stats_data_source': json.dumps(protocol_stats_data_source)})


def arp(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    chart_dict_all = arp_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'arp.html', {'chart_dict_all': chart_dict_all["chart_data"], 'metadata': chart_dict_all["metadata"]})


def darknet(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    chart_dict_all = darknet_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'darknet.html', {"packets_dist": chart_dict_all["packets_dist"],
        "protocols_dist": chart_dict_all["protocols_dist"],
        "src_ip_class_dist": chart_dict_all["src_ip_class_dist"],
        "dst_ip_class_dist": chart_dict_all["dst_ip_class_dist"],
        "tcp_targeted_ports": chart_dict_all["tcp_targeted_ports"],
        "udp_targeted_ports":chart_dict_all["udp_targeted_ports"]})


def dhcp(request):
    return render(request, 'dhcp.html')


def dns(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    dns_detection_dicts = dns_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'dns.html', {'dns_detection_dicts': dns_detection_dicts})

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
