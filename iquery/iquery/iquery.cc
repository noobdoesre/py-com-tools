#include <Windows.h>
#include <Objsafe.h>
#include <Tlhelp32.h>
#include <stdio.h>

#pragma comment(lib, "ole32")
#pragma comment(lib, "Advapi32")

static BOOL	comInit = FALSE;
typedef long PTR;

typedef HRESULT (__stdcall *getClassObjFn)(
  __in   REFCLSID rclsid,
  __in   REFIID riid,
  __out  LPVOID *ppv
);

/*
 */
class iQuery{
private:
	IUnknown	*iuk;
	IUnknown * queryInterfaceWorker(const char *iface);
	bool safeWorker(const char *iid, DWORD flags);
public:
	iQuery(const char *clsid = NULL) throw(const char *);
	~iQuery();

	bool isInterfaceSupported(const char *iface) throw(const char *);
	PTR getIFaceVTOffset(const char *iface) throw(const char *);
	bool isSafeScript(const char *iid);
	bool isSafeInit(const char *iid);
	bool coCreateUnknown(char *file, char *rclsid) throw(const char *);
};


void hexdump(void *pAddressIn, long  lSize)
{
 char szBuf[100];
 long lIndent = 1;
 long lOutLen, lIndex, lIndex2, lOutLen2;
 long lRelPos;
 struct { char *pData; unsigned long lSize; } buf;
 unsigned char *pTmp,ucTmp;
 unsigned char *pAddress = (unsigned char *)pAddressIn;

   buf.pData   = (char *)pAddress;
   buf.lSize   = lSize;

   while (buf.lSize > 0)
   {
      pTmp     = (unsigned char *)buf.pData;
      lOutLen  = (int)buf.lSize;
      if (lOutLen > 16)
          lOutLen = 16;

      // create a 64-character formatted output line:
      sprintf(szBuf, " >                            "
                     "                      "
                     "    %08lX", pTmp-pAddress);
      lOutLen2 = lOutLen;

      for(lIndex = 1+lIndent, lIndex2 = 53-15+lIndent, lRelPos = 0;
          lOutLen2;
          lOutLen2--, lIndex += 2, lIndex2++
         )
      {
         ucTmp = *pTmp++;

         sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
         if(!isprint(ucTmp))  ucTmp = '.'; // nonprintable char
         szBuf[lIndex2] = ucTmp;

         if (!(++lRelPos & 3))     // extra blank after 4 bytes
         {  lIndex++; szBuf[lIndex+2] = ' '; }
      }

      if (!(lRelPos & 3)) lIndex--;

      szBuf[lIndex  ]   = '<';
      szBuf[lIndex+1]   = ' ';

      printf("%s\n", szBuf);

      buf.pData   += lOutLen;
      buf.lSize   -= lOutLen;
   }
}

//
iQuery::iQuery(const char *clsid)
{
	CLSID	targetCLSID;
	OLECHAR	buf[0x200];

	iuk = NULL;

	//
	if(!comInit){
		comInit = TRUE;
		CoInitialize(NULL);
	}

	if(clsid == NULL)
		return;

	//convert CLSID to uni
	if(MultiByteToWideChar(CP_ACP, 0, clsid, -1, buf, sizeof(buf)/sizeof(buf[0])) == 0)
		throw("MultiByteToWideChar() failed");
	else if(FAILED(CLSIDFromString(buf, &targetCLSID)))
		throw("CLSIDFromString() failed");
	else if(FAILED(CoCreateInstance(targetCLSID, NULL, CLSCTX_INPROC_SERVER, IID_IUnknown, (void **)&this->iuk))){
		if(FAILED(CoCreateInstance(targetCLSID, NULL, CLSCTX_LOCAL_SERVER, IID_IUnknown, (void **)&this->iuk)))
			throw("CoCreateInstance() failed");
	}
}

iQuery::~iQuery()
{
	if(iuk != NULL){
		//printf("~iQuery():Releasing %p\n", iuk);
		//hexdump(iuk, 0x30);
		iuk->Release();
		iuk = NULL;
	}
}

//
bool iQuery::coCreateUnknown(char *file, char *rclsid)
{
	CLSID	targetCLSID;
	WCHAR	buf[0x200];
	HMODULE	hm;
	getClassObjFn	factoryFn = NULL;
	IClassFactory	*factory = NULL;
	HRESULT	hr;

	//printf("ENTR\n");
	if(iuk != NULL){
		//printf("coCreateUnknown():Releasing %p\n", iuk);
		//hexdump(iuk, 0x30);
		iuk->Release();
		iuk = NULL;
	}

	//convert CLSID to uni
	if(MultiByteToWideChar(CP_ACP, 0, rclsid, -1, buf, sizeof(buf)/sizeof(buf[0])) == 0){
		throw("MultiByteToWideChar() failed");
	}

	if(FAILED(CLSIDFromString(buf, &targetCLSID))){
		throw("CLSIDFromString() failed");
	}

	if(MultiByteToWideChar(CP_ACP, 0, file, -1, buf, sizeof(buf)/sizeof(buf[0])) == 0)
		throw("MultiByteToWideChar() failed");
	
	//printf("to uni\n");

	hm = LoadLibrary(buf);
	if(hm == NULL){
		LPVOID	error = NULL;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&error, 0, NULL);
		wprintf(L"Get last error %s\n", error);
		throw("LoadLibrary() failed");
	}
	//printf("Loaded lib\n");

	factoryFn = (getClassObjFn)GetProcAddress(hm, "DllGetClassObject");
	if(factoryFn == NULL)
		throw("Can't find DllGetClassObject!");
	//printf("Factoryfn @%p\n", factoryFn);

	if(FAILED(factoryFn(targetCLSID, IID_IClassFactory, (LPVOID *)&factory)))
		throw("factoryFn() failed");
	//printf("made class factory\n");

	if(FAILED( (hr = factory->CreateInstance(NULL, IID_IUnknown, (LPVOID *)&iuk)) )){
		//printf("FAIL %#x\n", hr);
		throw("CreateInstance() failed");
	}
	//printf("coCreateUnknown():Created instance %p\n", iuk);
	//iuk->AddRef();
	//hexdump(iuk, 0x100);
	//fflush(stdout);
	//getchar();
	

	factory->Release();	

	return TRUE;
}


//
bool iQuery::isSafeInit(const char *iid)
{
	return safeWorker(iid, INTERFACESAFE_FOR_UNTRUSTED_DATA);
}

//
bool iQuery::isSafeScript(const char *iid)
{
	return safeWorker(iid, INTERFACESAFE_FOR_UNTRUSTED_CALLER);
}

//
bool iQuery::safeWorker(const char *iid, DWORD flags)
{
	CLSID	targetCLSID;
	OLECHAR	buf[0x200];
	HRESULT	ret;
	IObjectSafety	*safe = NULL;

	safe = reinterpret_cast<IObjectSafety *>(queryInterfaceWorker("{CB5BDC81-93C1-11cf-8F20-00805F2CD064}"));
	if(safe == NULL)
		return FALSE;
	
	//convert CLSID to uni
	if(MultiByteToWideChar(CP_ACP, 0, iid, -1, buf, sizeof(buf)/sizeof(buf[0])) == 0){
		throw("MultiByteToWideChar() failed");
	}

	if(FAILED(CLSIDFromString(buf, &targetCLSID))){
		throw("CLSIDFromString() failed");
	}

	ret = safe->SetInterfaceSafetyOptions(targetCLSID, flags, flags);
	safe->Release();
	return ret == S_OK;
}

//
PTR getModBase(PTR addr)
{
	HANDLE	snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
	MODULEENTRY32	mod;
	BOOL	ret;

	mod.dwSize = sizeof(mod);
	for(ret = Module32First(snapShot, &mod); ret; ret = Module32Next(snapShot, &mod)){
		if(addr >= (PTR)mod.modBaseAddr && addr <= (PTR)mod.modBaseAddr + mod.modBaseSize)
			return addr - (PTR)mod.modBaseAddr;
	}
	return 0;
}

//
PTR iQuery::getIFaceVTOffset(const char *iface)
{
	PTR	addr = 0;
	IUnknown	*testInterface = NULL;
	
	//printf("getIFaceVTOffset() iuk %p\n", iuk);
	//hexdump(iuk, 0x100);
	testInterface = queryInterfaceWorker(iface);
	if(testInterface != NULL){
		addr = *(PTR *)testInterface;
		addr = getModBase(addr);
		testInterface->Release();
		//printf("getIFaceVTOffset(), releaed testINterafce %p yes, iuk %p\n", testInterface, iuk);
		//hexdump(iuk, 0x100);
	}
	return addr;
}

//
bool iQuery::isInterfaceSupported(const char *iface)
{
	IUnknown	*testInterface = NULL;

	//uh, this is weird, results in crashes in QT b/c it returns TRUE but doesn't increment refcount!!
	if(strcmp(iface, "{00000000-0000-0000-0000-000000000000}") == 0)
		return FALSE;

	testInterface = queryInterfaceWorker(iface);
	if(testInterface != NULL){
		//printf("Releasing %p\n", testInterface);
		//printf("isInterfaceSupported(%s) yes, iuk %p\n", iface, iuk);
		//hexdump(iuk, 0x100);
		testInterface->Release();
		//printf("isInterfaceSupported(), releaed testINterafce %p yes, iuk %p\n", testInterface, iuk);
		//hexdump(iuk, 0x100);
		return TRUE;
	}
	return FALSE;
}

//
IUnknown * iQuery::queryInterfaceWorker(const char *iface)
{
	OLECHAR	buf[0x200];
	IUnknown	*testInterface = NULL;
	CLSID	ifaceCLSID;
	HRESULT	hr;
		
	//printf("Entering quiworker, iuk %p\n", iuk);
	//hexdump(iuk, 0x100);
	if(iuk == NULL){
		throw("iuk is NULL!");
	}

	//convert CLSID to uni
	if(MultiByteToWideChar(CP_ACP, 0, iface, -1, buf, sizeof(buf)/sizeof(buf[0])) == 0){
		throw("MultiByteToWideChar() failed");
	}

	if(FAILED(CLSIDFromString(buf, &ifaceCLSID))){
		throw("CLSIDFromString() failed");
	}

	/**/
	__try{
		hr = iuk->QueryInterface(ifaceCLSID, (void **)&testInterface);
		if(hr == 0){
			return testInterface;
		}else{
			;
			//printf("%s is NOT support, %#x (%d)\n", iface, hr, hr);
		}
	}__except(EXCEPTION_EXECUTE_HANDLER){
		//spurious AVs in msxml?
		//printf("QueryFailed %p, test %p\n", iuk, testInterface);
		//hexdump(iuk, 0x100);
		throw("QueryInterface() failed due to AV");
	}

	return NULL;
}