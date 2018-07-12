from django.shortcuts import render

# Create your views here.
import json
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage

from .helper import protocol_hierarchy_analysis
from .helper import protocols_time_series_analysis
from .helper import arp_analysis
from .helper import port_scanning_analysis
from .helper import dns_analysis
from .helper import darknet_analysis
from .helper import sessions_analysis
from .helper import smtp_analysis
from .helper import dos_analysis


def index(request):
    return render(request, 'index.html')


def analyse(request):
    if request.method == 'POST':
        try:
            myfile = request.FILES['capture_file']
        except:
            return index(request)
        fs = FileSystemStorage()
        filename = fs.save(myfile.name, myfile)
        uploaded_file_url = fs.url(filename)
    else:
        try:
            uploaded_file_url = request.GET.get('uploaded_file_url', '')
            if len(uploaded_file_url) == 0:
                raise Exception
        except:
            return index(request)
    chart_dict = protocol_hierarchy_analysis.main(uploaded_file_url.lstrip('/'))
    protocol_stats_data_source = protocol_hierarchy_analysis.chart_dict_to_stats(chart_dict)
    protocols_time_series_dict = protocols_time_series_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'analyse.html', \
            {'uploaded_file_url': uploaded_file_url, \
              'protocols_analysis_data_source': json.dumps(chart_dict), \
              'protocol_stats_data_source': json.dumps(protocol_stats_data_source), \
             'protocols_time_series_data': json.dumps(protocols_time_series_dict)})


def arp(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    chart_dict_all = arp_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'arp.html', {'chart_dict_all': chart_dict_all["chart_data"], 'metadata': chart_dict_all["metadata"], 'uploaded_file_url': uploaded_file_url})


def darknet(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    chart_dict_all = darknet_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'darknet.html', {"packets_dist": chart_dict_all["packets_dist"],
        "protocols_dist": chart_dict_all["protocols_dist"],
        "src_ip_class_dist": chart_dict_all["src_ip_class_dist"],
        "dst_ip_class_dist": chart_dict_all["dst_ip_class_dist"],
        "tcp_targeted_ports": chart_dict_all["tcp_targeted_ports"],
        "udp_targeted_ports":chart_dict_all["udp_targeted_ports"],
        'uploaded_file_url': uploaded_file_url})


def dhcp(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    return render(request, 'dhcp.html', {'uploaded_file_url': uploaded_file_url})


def dns(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    dns_detection_dicts = dns_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'dns.html', {'dns_detection_dicts': dns_detection_dicts, 'uploaded_file_url': uploaded_file_url})

def dos(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    dos_detection_dicts = dos_analysis.main(uploaded_file_url.lstrip('/'))
    information_dict = {}
    if len(dos_detection_dicts['ping']) > 0:
        information_dict["ping_attack_list"] = dos_detection_dicts['ping']
    if len(dos_detection_dicts['land']) > 0:
        information_dict["land_attack_list"] = dos_detection_dicts['land']
    if len(dos_detection_dicts['mail']) > 0:
        information_dict["mail_attack_list"] = dos_detection_dicts['mail']
    information_dict["uploaded_file_url"] = uploaded_file_url
    return render(request, 'dos.html', information_dict)


def port_scanning(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    port_scanning_dicts = port_scanning_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'port_scanning.html', {'port_scanning_dicts': port_scanning_dicts, 'uploaded_file_url': uploaded_file_url})


def sessions(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    sessions_info = sessions_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'sessions.html', {'sessions_info': sessions_info, 'uploaded_file_url': uploaded_file_url})

def smtp(request):
    uploaded_file_url = request.GET.get('uploaded_file_url', '')
    smtp_dissections = smtp_analysis.main(uploaded_file_url.lstrip('/'))
    return render(request, 'smtp.html', {'smtp_dissections': smtp_dissections, 'uploaded_file_url': uploaded_file_url})

def about(request):
    return render(request, 'about.html')
