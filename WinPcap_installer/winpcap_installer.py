import platform
import os
import subprocess
from shutil import copy2

DLL_PACKET_NT4 			= 'Packet_nt4_x86.dll'
DLL_PACKET_NT5_x86 		= 'Packet_nt5_x86.dll'
DLL_PACKET_NT5_x64 		= 'Packet_nt5_x64.dll'
DLL_PACKET_Vista_x86 	= 'Packet_Vista_x86.dll'
DLL_PACKET_Vista_x64 	= 'Packet_Vista_x64.dll'
DLL_PACKET				= 'Packet.dll'
DLL_WPCAP_x86 			= 'wpcap_x86.dll'
DLL_WPCAP_x64 			= 'wpcap_x64.dll'
DLL_WPCAP				= 'wpcap.dll'
DLL_PTHREAD_VC 			= 'pthreadVC.dll'
DRIVER_NPF_NT4 			= 'drivers\\npf_nt4_x86.sys'
DRIVER_NPF_NT5_NT6_x86 	= 'drivers\\npf_nt5_nt6_x86.sys'
DRIVER_NPF_NT5_NT6_x64 	= 'drivers\\npf_nt5_nt6_x64.sys'
DRIVER_NPF 				= 'npf.sys'
DLL_DST_PATH			= 'C:\\windows\\System32'
DLL_DST_PATH_x86_64		= 'C:\\Windows\\sysWOW64'
DRIVER_DST_PATH 		= 'C:\\Windows\\System32\\Drivers'

def vprint(msg, verbose):
	if verbose:
		print('winpcap_installer: ' + msg)

def parse_win_version(version_str):
	tmp = version_str.split('.')
	if len(tmp) == 1 or len(tmp) == 2:
		return float(version_str)
	elif len(tmp) > 2:
		return float(tmp[0] + '.' + tmp[1])
	else:
		raise ValueError('incorrect win_version string')

def assert_windows():
	system = platform.system()
	if system != 'Windows':
		raise OSError('winpcap_installer is designed for Windows only')

def sys_cmd(cmd):
	fcmd = filter(len, cmd.split(' '))
	p = subprocess.Popen(fcmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	out, err = p.communicate()
	return out

def is_installed(verbose=False):
	assert_windows()
	version = parse_win_version(platform.win32_ver()[1])
	is_x64 = platform.machine().endswith('64')
	result = os.path.isfile(os.path.join(DLL_DST_PATH, DLL_PTHREAD_VC))
	result = result and os.path.isfile(os.path.join(DLL_DST_PATH, DLL_WPCAP))
	result = result and os.path.isfile(os.path.join(DLL_DST_PATH, DLL_PACKET))
	result = result and os.path.isfile(os.path.join(DRIVER_DST_PATH, DRIVER_NPF))
	if is_x64:
		result = result and os.path.isfile(os.path.join(DLL_DST_PATH_x86_64, DLL_WPCAP))
		result = result and os.path.isfile(os.path.join(DLL_DST_PATH_x86_64, DLL_PACKET))
	service_info = filter(len, sys_cmd('sc query npf').split('\r\n'))
	if len(service_info) < 3:
		result = False
	else:
		service_state = service_info[2].strip()
		if service_state.startswith('STATE') and service_state.endswith('RUNNING'):
			result = True
		else:
			result = False
	return result	

def install(winpcap_path='WinPcap', verbose=False):
	assert_windows()
	vprint('Preparing for installation', verbose)
	# 1. Choose what files to distribute
	version = parse_win_version(platform.win32_ver()[1])
	is_x64 = platform.machine().endswith('64')
	if is_x64:
		vprint('Detected platform: Windows NT {0} (x64)'.format(version), verbose)
	else:
		vprint('Detected platform: Windows NT {0} (x86)'.format(version), verbose)
	pthread_dll = os.path.join(winpcap_path, DLL_PTHREAD_VC)
	wpcap_dll_x86 = os.path.join(winpcap_path, DLL_WPCAP_x86)
	if is_x64:
		wpcap_dll_x64 = os.path.join(winpcap_path, DLL_WPCAP_x64)
	else:
		wpcap_dll_x64 = ''
	if version < 5.0:
		# NT 4.0 Windows or older
		packet_dll_x86 = os.path.join(winpcap_path, DLL_PACKET_NT4)
		packet_dll_x64 = ''
		driver_sys = os.path.join(winpcap_path, DRIVER_NPF_NT4)
	elif version < 6.0:
		# NT 5.0 Windows or older
		packet_dll_x86 = os.path.join(winpcap_path, DLL_PACKET_NT5_x86)
		if is_x64:
			packet_dll_x64 = os.path.join(winpcap_path, DLL_PACKET_NT5_x64)
			driver_sys = os.path.join(winpcap_path, DRIVER_NPF_NT5_NT6_x64)
		else:
			packet_dll_x64 = ''
			driver_sys = os.path.join(winpcap_path, DRIVER_NPF_NT5_NT6_x86)
	else:
		# NT 6.0 Windows or newer
		packet_dll_x86 = os.path.join(winpcap_path, DLL_PACKET_Vista_x86)
		if is_x64:
			packet_dll_x64 = os.path.join(winpcap_path, DLL_PACKET_Vista_x64)
			driver_sys = os.path.join(winpcap_path, DRIVER_NPF_NT5_NT6_x64)
		else:
			packet_dll_x64 = ''
			driver_sys = os.path.join(winpcap_path, DRIVER_NPF_NT5_NT6_x86)
	vprint('Files to copy:', verbose)
	if verbose:
		for file in (pthread_dll, wpcap_dll_x86, wpcap_dll_x64, packet_dll_x86, packet_dll_x64, driver_sys):
			if file != '':
				print('    {}'.format(file))
	# 2. Copy files
	copy2(pthread_dll, os.path.join(DLL_DST_PATH, DLL_PTHREAD_VC))
	if wpcap_dll_x64 == '':
		copy2(wpcap_dll_x86, os.path.join(DLL_DST_PATH, DLL_WPCAP))
	else:
		copy2(wpcap_dll_x86, os.path.join(DLL_DST_PATH_x86_64, DLL_WPCAP))
		copy2(wpcap_dll_x64, os.path.join(DLL_DST_PATH, DLL_WPCAP))
	if packet_dll_x64 == '':
		copy2(packet_dll_x86, os.path.join(DLL_DST_PATH, DLL_PACKET))
	else:
		copy2(packet_dll_x86, os.path.join(DLL_DST_PATH_x86_64, DLL_PACKET))
		copy2(packet_dll_x64, os.path.join(DLL_DST_PATH, DLL_PACKET))
	copy2(driver_sys, os.path.join(DRIVER_DST_PATH, DRIVER_NPF))
	# 3. Start npf driver as a service
	vprint('Registering npf as a service', verbose)
	os.system("""	sc create npf binPath= system32\\drivers\\npf.sys type= kernel
		 			start= auto error= normal tag= no DisplayName= \"NetGroup Packet Filter Driver\" """)
	os.system('sc start npf')
	vprint('Installation complete', verbose)

def uninstall(verbose=False):
	vprint('Preparing for cleanup', verbose)
	assert_windows()
	version = parse_win_version(platform.win32_ver()[1])
	is_x64 = platform.machine().endswith('64')
	# 1. Stop service
	vprint('Stopping and deleting npf service', verbose)
	os.system('sc stop npf')
	os.system('sc delete npf')
	# 2. Delete files
	vprint('Deleting files', verbose)
	if os.path.isfile(os.path.join(DLL_DST_PATH, DLL_PTHREAD_VC)):
		os.remove(os.path.join(DLL_DST_PATH, DLL_PTHREAD_VC))
	if os.path.isfile(os.path.join(DLL_DST_PATH, DLL_WPCAP)):
		os.remove(os.path.join(DLL_DST_PATH, DLL_WPCAP))
	if os.path.isfile(os.path.join(DLL_DST_PATH, DLL_PACKET)):
		os.remove(os.path.join(DLL_DST_PATH, DLL_PACKET))
	if os.path.isfile(os.path.join(DRIVER_DST_PATH, DRIVER_NPF)):
		os.remove(os.path.join(DRIVER_DST_PATH, DRIVER_NPF))
	if is_x64:
		if os.path.isfile(os.path.join(DLL_DST_PATH_x86_64, DLL_WPCAP)):
			os.remove(os.path.join(DLL_DST_PATH_x86_64, DLL_WPCAP))
		if os.path.isfile(os.path.join(DLL_DST_PATH_x86_64, DLL_PACKET)):
			os.remove(os.path.join(DLL_DST_PATH_x86_64, DLL_PACKET))
	vprint('Cleanup complete', verbose)
