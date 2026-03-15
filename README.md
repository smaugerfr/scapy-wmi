<!-- start_ppi_description -->
# Scapy WMI

This package provides a plugin that hooks into Scapy to register [MS-WMI] dissector/builder and a new WMI layer with its client.

It has been designed to execute [WMI](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) (Windows Management Instrumentation) queries, retrieve objects, and invoke methods on remote Windows machines over the network (tcp/135). 

It allows administrators to interact with WMI classes, fetch system information, and perform administrative tasks—such as querying processes, services, or hardware details—without direct access to the target machine. The tool leverages standard WMI protocols and requires only network connectivity (port 135) and valid credentials for secure remote execution.

It also can be used as offensive purpose as it allows to remotely create new process, but only use this in authorized environment

https://github.com/user-attachments/assets/700e250e-ac71-498b-b2c8-ca000d913ca4

## Usage
By adding follwing to `~/.config/scapy/prestart.py`
```
from scapy.config import conf
conf.load_extensions = ["scapy-wmi"]
```
OR load at runtime
```
from scapy.config import conf
conf.exts.load("scapy-wmi")
```

#### Verify
```
$ scapy
>>> from scapy.config import conf
>>> print(conf.exts)
```
## Installation
```
$ pip install .
```

## Example
For a simple usage see `main.py`, it shows also how to use type checking

<!-- stop_ppi_description -->
