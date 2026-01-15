<!-- start_ppi_description -->
# Scapy-wmi

This package provides a plugin that hooks into Scapy to register [MS-WMI] dissector/builder and a new WMI layer with its client.

### Usage
By adding follwing to `~/.config/scapy/prestart.py`
```
from scapy.config import conf
conf.load_extensions = ["scapy-wmi"]
```
OR load at runtime
```
conf.load_extensions.append("scapy-wmi")
conf.exts.loadall()
```

##### verify
```
$ scapy
>>> from scapy.config import conf
>>> print(conf.exts)
```
<!-- stop_ppi_description -->
#### Installation
```
$ cd scapy-wmi
$ pip install .
```
