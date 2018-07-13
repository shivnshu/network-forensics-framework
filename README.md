# network-forensics-framework
[![Build Status](https://travis-ci.com/shivnshu/network-forensics.svg?token=xzu4Fpk8ohJLJEshzQEf&branch=master)](https://travis-ci.com/shivnshu/network-forensics)

## Directory Structure
```
├── captures
│   └── ..............................:: sample pcap files
├── doc
|   └── ..............................:: scripts documentation
├── scripts
|   └── ..............................:: python scripts
├── webapp
|   ├── net_forensics
|   |   ├── helper
|   |   |   └── ......................:: python script acting as middleware
|   |   ├── static
|   |   |   └── ......................:: static img, css and js files
|   |   ├── templates
|   |   |   └── ......................:: django html templates for webpages
|   |   ├── fusioncharts.py ..........:: fusioncharts class declaration
|   |   ├── scripts ..................:: softlink to top level scripts folder
|   |   ├── views.py
|   ├── webapp
|   └── manage.py
├── Dockerfile
├── README.md
└── test_main.py .....................:: python tests
```

## Installation

### Docker Installation

### Native Installation

## Screenshots
![](screenshots/analyse.png)

## License
See [LICENSE](https://github.com/shivnshu/network-forensics-framework/blob/master/LICENSE) for more information.
