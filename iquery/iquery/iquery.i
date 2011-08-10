/* cquery.i */
%module iquery
%{
#include <Windows.h>
#include <Objsafe.h>
#include <WinDef.h>

typedef long PTR;

class iQuery{
private:
    IUnknown    *iuk;
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
%}
#include <Windows.h>
#include <Objsafe.h>
#include <WinDef.h>

typedef long PTR;

class iQuery{
private:
    IUnknown    *iuk;
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
