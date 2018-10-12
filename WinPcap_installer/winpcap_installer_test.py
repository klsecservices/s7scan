import sys
import winpcap_installer as wpinst

def test_install():
	wpinst.install(verbose=True)

def test_uninstall():
	wpinst.uninstall(verbose=True)

def test_is_installed():
	if wpinst.is_installed(verbose=True):
		print("WinPcap is installed on this machine")
	else:
		print("WinPcap is not installed on this machine")

if len(sys.argv) > 1:
	if sys.argv[1] == 'install':
		test_install()
	elif sys.argv[1] == 'uninstall':
		test_uninstall()
	elif sys.argv[1] == 'check':
		test_is_installed()
	else:
		print('please specify what function to test [install/uninstall/check]')
		sys.exit()
else:
	print('please specify what function to test [install/uninstall/check]')