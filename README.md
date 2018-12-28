# s7scan  

## General description
**s7scan** is a tool that scans networks, enumerates Siemens PLCs and gathers basic information about them, such as PLC firmware and hardwaare version, network configuration and security parameters.
It is completely written on Python.  
The tool uses S7 protocol to connect to talk toPLCs. More specifically, it performs "Read SZL" to get information about controllers. Formats of these requests are documented in "Siemens SIMATIC System Software for S7-300/400 System and
Standard Functions. Reference manual", which can be found at the following link:  https://cache.industry.siemens.com/dl/files/574/1214574/att_44504/v1/SFC_e.pdf  
Main features of the utility:
1. Identifying all active PLCs in a particular network;
2. Obtaining basic information about each PLC:  
    a. PLC type;  
    b. Software version;  
    c. Hardware version;  
    d. Protection settings applied to the PLC (key position, r/w/rw access rights);  
    e. Network configuration of the PLC.  
3. Supporting both TCP/IP and LLC transport protocols.
4. Ability to be built as a stand-alone binary with pyinstaller  

**s7scan** is based on the utility called "plcscan" from Dmitry Efanov (Positive Research). Comparing this old version, here are main differences:  
    - Support of low-level LLC protocol;  
    - Showing protection configuration of PLCs;  
    - Improvements fo default COTP TSAP checking procedure in order to find all PLCs within racks;  
    - Improved stability.  
    
The tool is designed to use scapy for crafting and sending low-level LLC packets. Still, for TCP/IP communications it uses standard OS socket interface for simplicity and stability.  

## What is this tool actually for?
The main purpose of the tool providing technical specialists/security auditors the ability to enumerate PLCs for that additional security configuration and/or firmware updates are needed.

## Installation
Actual installation is not required. Just download **s7scan** and run python with s7scan.py  
The tool currently depends on scapy, so scapy installation is required.
The tool currently works with Python 2 only

## Use cases
You can use s7scan in the following form:
1. Usage with python and scapy installed on the machine. In this case you only need to download **s7scan**, go to its directory and run "python s7scan.py" in the console.
2. Usage on computers without python. In this case the option is to use pyinstaller. Install it, go to s7scan folder and run

```
"pyinstaller --onefile s7scan.py"
```
to build a stand-alone binary. Then distribute this binary to the target computer and use it.  
Both use-cases are acceptable on Linux/Windows/Mac.  
Alternatively, you can use pre-built executables built by pyinstaller in **dist** directory.  

**Note:** on Windows you will need WinPcap (or Npcap) if you want to scan LLC networks. If installing it is not an option, you have 2 alternatives:  
1. Download and run portable version of Wireshark;
2. Use the script winpcap_installer_test.py that is included in s7scan. Run 
```
winpcap_installer_test.py install
```
command in your console, and it will perform silent install of WinPcap. After scanning you can simply run 
```
winpcap_installer.py uninstall
```
to get rid of all WinPcap files. You can also run 
```
winpcap_installer_test.py check
```
in order to check whether WinPcap is installed on the machine.  

## Kudos
`@_moradek_` at twitter for help with development    

## Disclaimer of warranty

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. 
EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES 
PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF 
THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST 
OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.  
IF ANYONE BELIEVES THAT THIS TOOL HAVE BEEN VIOLATED SOME COPYRIGHTS, PLEASE EMAIL US, 
AND ALL THE NECESSARY CHANGES WILL BE MADE.

## Less formal disclaimer (or why we had to write the disclaimer at all)

This open-source tool was developed for internal purposes. It was tested on 
several different PLC families: S7-300, S7-400 and S7-1500. Nevertheless, it's 
still just a result of a research project, and as always, it may be vulnerable to 
mistakes and lack of knowledge under some hypothetical circumstances. Neither the
author of the tool nor Kaspersky Lab are responsible for any possible
damage caused by the tool to the industrial equipment or any technological and 
business processes. Use the tool only after considering the consequences, and at
your own risk.  

## Contacts
Please feel free to contact us if you have any questions/suggestions/feedback related 
to the tool. Use the following coordinates:  
    **Twitter:** @zero_wf from @kl_secservices  
    **Github:**  @klsecservices  
Any contribution to the project is always welcome!
