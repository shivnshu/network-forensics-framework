from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse
from django.core.files.storage import FileSystemStorage


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
    return render(request, 'analyse.html', \
            {'uploaded_file_url': uploaded_file_url, \
             'uploaded_file_name': myfile.name})


def arp(request):
    return render(request, 'arp.html')


def darknet(request):
    return render(request, 'darknet.html')


def dhcp(request):
    return render(request, 'dhcp.html')


def dns(request):
    return render(request, 'dns.html')


def port_scanning(request):
    return render(request, 'port_scanning.html')


def smtp(request):
    return render(request, 'smtp.html')
