FROM ubuntu:18.04

RUN apt-get update && apt-get install python3 python3-pip -y

ADD requirements.txt .
RUN pip3 install -r requirements.txt

WORKDIR network-forensics-framework
ADD . .
EXPOSE 8000

WORKDIR webapp
ENTRYPOINT ["python3", "manage.py", "runserver", "0.0.0.0:8000"]
