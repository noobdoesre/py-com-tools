#!/cygdrive/c/Python27/python.exe

import os
import sys
import _winreg
import pythoncom
import iquery


#some indexes into the tuples returned by various itypelib/info funcs

#pywin32/com/win32com/src/extensions/PyIType.cpp
IATTR_IID = 0
IATTR_LCID = 1
IATTR_MEMIDCONSTR = 2
IATTR_MEMIDDESTR = 3
IATTR_CBSZINST = 4
IATTR_TYPEKIND = 5
IATTR_CFUNCS = 6
IATTR_CVARS = 7
IATTR_CIMPLTYPES = 8
IATTR_CSZVT = 9
IATTR_CBALIGN = 10
IATTR_WTYPEFLAGS = 11
IATTR_MAJORV = 12
IATTR_MINORV = 13
IATTR_DESCALIAS = 14
IATTR_IDLDESC = 15

DOC_NAME = 0
DOC_DOCSTR = 1
DOC_HELPCTX = 2
DOC_HELPFILE = 3

LATTR_IID = 0
LATTR_LCID = 1
LATTR_SYSKIND = 2
LATTR_MAJOR = 3
LATTR_MINOR = 4
LATTR_FLAGS = 5

#FUNCDESC flags
INVOKE_FUNC = 1
INVOKE_PROPERTYGET = 2
INVOKE_PROPERTYPUT = 4
INVOKE_PROPERTYPUTREF = 8
FUNC_VIRTUAL = 0
FUNC_PUREVIRTUAL = 1
FUNC_NONVIRTUAL = 2
FUNC_STATIC = 3
FUNC_DISPATCH = 4
funckindmap = {
        FUNC_VIRTUAL:'[virtual]',
        FUNC_PUREVIRTUAL:'[purevirtual]',
        FUNC_NONVIRTUAL:'[nonvirtual]',
        FUNC_STATIC:'[static]',
        FUNC_DISPATCH:'[dispatch]',
}

#map a TYPEKIND enum into a string
typekindmap = {
    pythoncom.TKIND_ENUM : 'Enumeration',
    pythoncom.TKIND_RECORD : 'Record',
    pythoncom.TKIND_MODULE : 'Module',
    pythoncom.TKIND_INTERFACE : 'Interface',
    pythoncom.TKIND_DISPATCH : 'Dispatch',
    pythoncom.TKIND_COCLASS : 'CoClass',
    pythoncom.TKIND_ALIAS : 'Alias',
    pythoncom.TKIND_UNION : 'Union'
}

#variant support
variantTypeMap = {pythoncom.VT_EMPTY: "Empty",
        pythoncom.VT_NULL: "NULL",
        pythoncom.VT_I2: "I2",
        pythoncom.VT_I4: "I4",
        pythoncom.VT_R4: "R4",
        pythoncom.VT_R8: "R8",
        pythoncom.VT_CY: "CY",
        pythoncom.VT_DATE: "Date",
        pythoncom.VT_BSTR: "BSTR",
        pythoncom.VT_DISPATCH: "IDispatch",
        pythoncom.VT_ERROR: "Error",
        pythoncom.VT_BOOL: "BOOL",
        pythoncom.VT_VARIANT: "Variant",
        pythoncom.VT_UNKNOWN: "IUnknown",
        pythoncom.VT_DECIMAL: "Decimal",
        pythoncom.VT_I1: "I1",
        pythoncom.VT_UI1: "UI1",
        pythoncom.VT_UI2: "UI2",
        pythoncom.VT_UI4: "UI4",
        pythoncom.VT_I8: "I8",
        pythoncom.VT_UI8: "UI8",
        pythoncom.VT_INT: "INT",
        pythoncom.VT_UINT: "UINT",
        pythoncom.VT_VOID: "VOID",
        pythoncom.VT_HRESULT: "HRESULT",
        pythoncom.VT_PTR: "*",
        pythoncom.VT_SAFEARRAY: "SafeArray",
        pythoncom.VT_CARRAY: "C Array",
        pythoncom.VT_USERDEFINED: "UserDefined",
        pythoncom.VT_LPSTR: "LPSTR",
        pythoncom.VT_LPWSTR: "LPWSTR",
        pythoncom.VT_FILETIME: "FILETIME",
        pythoncom.VT_BLOB: "Blob",
        pythoncom.VT_STREAM: "IStream",
        pythoncom.VT_STORAGE: "IStorage",
        pythoncom.VT_STORED_OBJECT: "StoredObject",
        pythoncom.VT_STREAMED_OBJECT: "StreamedObject",
        pythoncom.VT_BLOB_OBJECT: "BlobObject",
        pythoncom.VT_CF: "CF",
        pythoncom.VT_CLSID: "CLSID",
}

#
variantFlagsMap = [ (pythoncom.VT_VECTOR, "Vector"),
           (pythoncom.VT_ARRAY, "Array"),
           (pythoncom.VT_BYREF, "ByRef"),
           (pythoncom.VT_RESERVED, "Reserved"),
]

#
class funcDesc(object):

    def __init__(self, name, desc):
        self.name = name
        self.ret = None
        self.args = []  #list of (name, type) tuples
        self.desc = desc

    #
    def addArg(self, aName, aType):
        self.args.append((aName, self.getPrettyType(aType)))

    #
    def setRet(self, ret):
        self.ret = self.getPrettyType(ret)

    #
    def flagStr(self):
        flags = self.desc.wFuncFlags

        out = "["
        if flags & pythoncom.FUNCFLAG_FHIDDEN:
            out += "HIDDEN]|"
        return out + "]"
    #
    def getPrettyType(self, eDesc):
        typ, flags, default = eDesc
        atyp = self.MakeReturnType(typ)
        
        #toggle ptrs, ghetto
        cur = 0
        res = atyp
        while atyp[cur:cur+2] == "* ":
            if cur == 0:
                res += " "
            cur += 2
            res += "*"
        
        if cur == 0:
            return res[cur:]
        else:
            return res[cur:] + " "
    
    #
    def MakeReturnTypeName(self, typ):
        justtyp = typ & pythoncom.VT_TYPEMASK
        try:
            typname = variantTypeMap[justtyp]
        except KeyError:
            typname = "?Bad type?"
        for (flag, desc) in variantFlagsMap:
            if flag & typ:
                typname = "%s(%s)" % (desc, typname)
        return typname

    def MakeReturnType(self, returnTypeDesc):
        if type(returnTypeDesc)==type(()):
            first = returnTypeDesc[0]
            result = self.MakeReturnType(first)
            if first != pythoncom.VT_USERDEFINED:
                result = result + " " + self.MakeReturnType(returnTypeDesc[1])
            return result
        else:
            return self.MakeReturnTypeName(returnTypeDesc)

    #
    def __str__(self):
        out = "%#x  "  % self.desc.oVft + self.ret + " " + self.name + "("
        for arg in self.args:
            out += "%s %s," % (arg[1], arg[0])
        return out + ") "   # + self.flagStr()

# base class for typeinfo entries, pythoncom.TKIND_*
class tkindBase(object):

    def __init__(self, tkind, **kwargs):
        self.kindType = tkind
        self.kindName = typekindmap[tkind]
        self.infoEntry = kwargs["infoEntry"]
        docEntry = kwargs["docEntry"]
        self.name = self.entryName = docEntry[DOC_NAME]
        self.entryDocStr = docEntry[DOC_DOCSTR]
        self.entryHelpCtx = docEntry[DOC_HELPCTX]
        self.entryHelpFile = docEntry[DOC_HELPFILE]

    def parse(self):
        self.attr = self.infoEntry.GetTypeAttr()
        self.iid = str.upper(str(self.attr[IATTR_IID]))
        #print "base.parse()"
    
    def getFlagStr(self, flags):
        out = "["

        if flags & pythoncom.TYPEFLAG_FAPPOBJECT:
            out += "FAPPOBJECT|"
        if flags & pythoncom.TYPEFLAG_FCANCREATE:
            out += "FANCREATE|"
        if flags & pythoncom.TYPEFLAG_FLICENSED:
            out += "FLICENSED|"
        if flags & pythoncom.TYPEFLAG_FPREDECLID:
            out += "FPREDECLID|"
        if flags & pythoncom.TYPEFLAG_FHIDDEN:
            out += "FHIDDEN|"
        if flags & pythoncom.TYPEFLAG_FCONTROL:
            out += "FCONTROL|"
        if flags & pythoncom.TYPEFLAG_FDUAL:
            out += "FDUAL|"
        if flags & pythoncom.TYPEFLAG_FNONEXTENSIBLE:
            out += "FNONEXTENSIBLE|"
        if flags & pythoncom.TYPEFLAG_FOLEAUTOMATION:
            out += "FOLEAUTOMATION|"
        if flags & pythoncom.TYPEFLAG_FRESTRICTED:
            out += "FRESTRICTED|"
        if flags & pythoncom.TYPEFLAG_FAGGREGATABLE:
            out += "FAGGREGATABLE|"
        if flags & pythoncom.TYPEFLAG_FREPLACEABLE:
            out += "FREPLACEABLE|"
        if flags & pythoncom.TYPEFLAG_FDISPATCHABLE:
            out += "FDISPATCHABLE|"
        if flags & pythoncom.TYPEFLAG_FREVERSEBIND:
            out += "FREVERSEBIND"
        return out + "]"

    def __str__(self):
        info = self.infoEntry
        out = "%s %s %s\n" % (self.kindName, self.entryName, self.attr[IATTR_IID])
        out += "Flags: %s\n" % (self.getFlagStr(self.attr[IATTR_WTYPEFLAGS]))
        out += "Doc: %s, %s, %d, %s\n" % (self.entryName, self.entryDocStr,
                                            self.entryHelpCtx, self.entryHelpFile)
        return out

# TKIND_INTERFACE | TKIND_DISPATCH
class tInterface(tkindBase):

    def __init__(self, tkind, **kwargs):
        super(tInterface, self).__init__(tkind, **kwargs)
        self.base = self.impl = None

    def parse(self):

        super(tInterface, self).parse()
        
        #_HiddenInterface appears to be known and bitched about on internets
        if ( (self.kindType == pythoncom.TKIND_DISPATCH or
                self.kindType == pythoncom.TKIND_INTERFACE) and
                self.attr[IATTR_CIMPLTYPES] == 0 and
                self.attr[IATTR_CSZVT] != 0 and
                self.entryName != "IUnknown" and
                self.entryName != "_HiddenInterface"
                ):
            print "WARNING: %s interface|dispatch cimpltypes == 0, vft sz %d\n" % (self.entryName,
                    self.attr[IATTR_CSZVT])
            #sys.exit(1)

        #get implemented interfaces
        for xi in xrange(0, self.attr[IATTR_CIMPLTYPES]):
            try:
                impType = self.infoEntry.GetRefTypeOfImplType(xi)
                impInfo = self.infoEntry.GetRefTypeInfo(impType)
                tlb2, index = impInfo.GetContainingTypeLib()
                doc2 = tlb2.GetDocumentation(index)
                impAttr = impInfo.GetTypeAttr()
                impIID = impAttr[IATTR_IID]
            except pythoncom.com_error, (hr, msg, exc, arg):
                print "pycom error: %s %s %s" % (msg, impType, impInfo)
                print "ERROR getting imp interface (%s) for %s" % (impType, self.entryName)
                print str(self)
                raise()
                sys.exit(1)
            self.impl = str(impIID)
    
    def __str__(self):
        out = super(tInterface, self).__str__()
        out += "Attr: sz %d, nfuncs %d, nvars %d, nintsimp %d, vftsz %d\n" % \
                        (self.attr[IATTR_CBSZINST], self.attr[IATTR_CFUNCS], self.attr[IATTR_CVARS],
                        self.attr[IATTR_CIMPLTYPES], self.attr[IATTR_CSZVT])
        out += self.hierStr() + "\n"
        out += self.vtableStr() + "\n"
        return out

    #
    def getVtable(self):
        if self.base:
            vt = self.base.getVtable()
        else:
            vt = []

        #in a dispatch the first 7 elems are just iuk+idisp
        if self.kindType == pythoncom.TKIND_DISPATCH:
            start = 7
        else:
            start = 0

        #
        info = self.infoEntry
        for xi in xrange(start, self.attr[IATTR_CFUNCS]):
            func = info.GetFuncDesc(xi)
            doc = info.GetDocumentation(func.memid)
            if (func.invkind & INVOKE_PROPERTYGET):
                fName = "get_%s" % doc[0]
            elif (func.invkind & INVOKE_PROPERTYPUT):
                fName = "put_%s" % doc[0]
            elif (func.invkind & INVOKE_PROPERTYPUTREF):
                fName = "putByRef_%s" % doc[0]
            else:
                fName = doc[0]

            curFunc = funcDesc(fName, func)
            curFunc.setRet(func.rettype)

            #build args
            names = list(info.GetNames(func.memid))
            names.reverse()
            names.pop()
            for arg in func.args:

                try:
                    name = names.pop()
                except IndexError:
                    name = "_"

                curFunc.addArg(name, arg)

            vt.append(curFunc)
            
        return vt

    #
    def vtableStr(self):
        vt = self.getVtable()
        out = ""
        for func in vt:
            out += str(func) + "\n"

        return out


    #get a string that traverses the inheritance hierarchy and lays out the vtable
    def hierStr(self):

        if self.base:
            return self.entryName + ":" + self.base.hierStr()
        else:
            return self.entryName
 
# TKIND_COCLASS
class tCoClass(tkindBase):

    def __init__(self, tkind, **kwargs):
        super(tCoClass, self).__init__(tkind, **kwargs)

    def parse(self):

        super(tCoClass, self).parse()

    def canCreate(self):
        if not self.attr:
            return False
        return self.attr[IATTR_WTYPEFLAGS] & pythoncom.TYPEFLAG_FCANCREATE

    def __str__(self):
        out = super(tCoClass, self).__str__()
        out += "Attr: sz %d, nfuncs %d, nvars %d, nintsimp %d, vftsz %d, flags %s\n" % \
                        (self.attr[IATTR_CBSZINST], self.attr[IATTR_CFUNCS], self.attr[IATTR_CVARS],
                        self.attr[IATTR_CIMPLTYPES], self.attr[IATTR_CSZVT],
                        self.getFlagStr(self.attr[IATTR_WTYPEFLAGS]))

        #get implemented interfaces
        for xi in xrange(0, self.attr[IATTR_CIMPLTYPES]):
            try:
                impType = self.infoEntry.GetRefTypeOfImplType(xi)
                impInfo = self.infoEntry.GetRefTypeInfo(impType)
                attr = impInfo.GetTypeAttr()
                tlb2, index = impInfo.GetContainingTypeLib()
                doc2 = tlb2.GetDocumentation(index)
                out += "\tInterface %s (%#x)%s\n" % (doc2[0], attr[IATTR_WTYPEFLAGS],
                                        self.getFlagStr(attr[IATTR_WTYPEFLAGS]))
            except pythoncom.com_error, (hr, msg, exc, arg):
                print "pycom error: %s" % (msg)
                print "Error getting imp interface (%s) for %s" % (impType, self.entryName)
                print out
                #sys.exit(1)

        return out + "\n"

# TKIND_ALIAS
class tAlias(tkindBase):

    def __init__(self, tkind, **kwargs):
        super(tAlias, self).__init__(tkind, **kwargs)

    def parse(self):

        super(tAlias, self).parse()

    def __str__(self):
        out = super(tAlias, self).__str__()
        out += "Attr: sz %d, nfuncs %d, nvars %d, nintsimp %d, vftsz %d, alias %s\n" % \
                        (self.attr[IATTR_CBSZINST], self.attr[IATTR_CFUNCS], self.attr[IATTR_CVARS],
                        self.attr[IATTR_CIMPLTYPES], self.attr[IATTR_CSZVT],
                        self.attr[IATTR_DESCALIAS])

        #get implemented interfaces
        for xi in xrange(0, self.attr[IATTR_CIMPLTYPES]):
            try:
                impType = self.infoEntry.GetRefTypeOfImplType(xi)
                impInfo = self.infoEntry.GetRefTypeInfo(impType)
                tlb2, index = impInfo.GetContainingTypeLib()
                doc2 = tlb2.GetDocumentation(index)
                out += "\tInterface %s\n" % doc2[0]
            except pythoncom.com_error, (hr, msg, exc, arg):
                print "pycom error: %s" % (msg)
                print "Error getting imp interface (%s) for %s" % (impType, self.entryName)
                sys.exit(1)

        return out + "\n"



#ghetto class factory
tKindFactory = { pythoncom.TKIND_INTERFACE:tInterface,\
                pythoncom.TKIND_DISPATCH:tInterface,\
                pythoncom.TKIND_COCLASS:tCoClass,\
                pythoncom.TKIND_ALIAS:tAlias\
                }

#
def createTKind(tkind, **kwargs):
    try:
        return tKindFactory[tkind](tkind, **kwargs)
    except KeyError:
        return None

#
class typeLib(object):

    #guid is None for .tlb files passed to us that are not from the registry
    def __init__(self, tlbFile, guid=None):
        self.tlbFile = tlbFile
        self.guid = None
        
        self.typeEnts = []

        #crappy uninstallers leave around typelib entries it seems
        if not os.path.exists(tlbFile):
            #print "WARNING: typelib file %s no longer exists" % (tlbFile)
            raise(OSError)
        
        try:
            self.itlb = pythoncom.LoadTypeLib(tlbFile)
        except pythoncom.com_error, (hr, msg, exc, arg):
            #print "WARNING: Tlib error %s for %s" % (msg, tlbFile)
            raise(OSError)

        self.parse()

    def parse(self):

        itlb = self.itlb

        #TLB documentation
        tlbDoc = itlb.GetDocumentation(-1)
        self.tlbName = tlbDoc[DOC_NAME]
        self.tlbDocStr = tlbDoc[DOC_DOCSTR]
        self.tlbHelpCtx = tlbDoc[DOC_HELPCTX]
        self.tlbHelpFile = tlbDoc[DOC_HELPFILE]

        #TLB attributes
        tlbAttr = itlb.GetLibAttr()

        if self.guid and self.guid != tlbAttr[LATTR_IID]:
            print "WARNING: tlib guid (%s) != guid (%s)" % (self.guid, tlbAttr[LATTR_IID])
            sys.exit(1)
        else:
            self.guid = str(tlbAttr[LATTR_IID])
        
        self.lcid = tlbAttr[LATTR_LCID]
        self.syskind = tlbAttr[LATTR_SYSKIND]
        self.major = tlbAttr[LATTR_MAJOR]
        self.minor = tlbAttr[LATTR_MINOR]
        self.flags = tlbAttr[LATTR_FLAGS]

        #TLB type info
        self.tInfoCount = itlb.GetTypeInfoCount()
        for i in xrange(self.tInfoCount):
            tkind = itlb.GetTypeInfoType(i)
            args = {}
            args["docEntry"] = itlb.GetDocumentation(i)
            args["infoEntry"] = itlb.GetTypeInfo(i)
            entry = createTKind(tkind, **args)
            if entry:
                entry.parse()
                self.typeEnts.append(entry)

    def __str__(self):
        out = "Typelib file %s\n" % (self.tlbFile)
        out += "Doc: %s, %s, %d, %s\n" % (self.tlbName, self.tlbDocStr,
                                            self.tlbHelpCtx, self.tlbHelpFile)
        out += "Attr: %s, lcid %d, syskind %d, version %d.%d, flags %#x (%s)\n" % \
                        (self.guid, self.lcid, self.syskind,
                            self.major, self.minor, self.flags, self.flagStr(self.flags))

        out += "Dumping entries...\n\n"
        for ent in self.typeEnts:
            out += str(ent) + "\n"

        return out

    #http://msdn.microsoft.com/en-us/library/cc237789(v=prot.13).aspx
    def flagStr(self, flags):
        out = ""
        if flags & 1:
            out += "[restricted]"
        if flags & 2:
            out += "[control]"
        if flags & 4:
            out += "[hidden]"
        if flags & 8:
            out += "[diskimage]"
        return out

    #
    def getClasses(self):

        classes = []
        for tEntry in self.typeEnts:
            if(tEntry.kindType == pythoncom.TKIND_COCLASS):
                classes.append(tEntry)

        return classes

    #
    def getInterfaces(self):

        ints = []
        for tEntry in self.typeEnts:
            if(tEntry.kindType == pythoncom.TKIND_INTERFACE or
                    tEntry.kindType == pythoncom.TKIND_DISPATCH):
                ints.append(tEntry)

        return ints

#simple manager for typelib entries
class typeLibMan(object):

    #
    def __init__(self, iMan):
        self.tlibs = {}
        self.iMan = iMan

    def getInterfaces(self):
        ints = []
        for guid, tlbs in self.tlibs.iteritems():
            for tlb in tlbs:
                ints.extend(tlb.getInterfaces())

        return ints
    #
    def __str__(self):
        out = ""
        for guid, tlbs in self.tlibs.iteritems():
            for tlb in tlbs:
                out += str(tlb)

        return out

    #
    def getLibs(self):
        for guid, tlbs in self.tlibs.iteritems():
            for tlb in tlbs:
                yield tlb
    #
    def getLib(self, guid, majorVers):
        try:
            tlibs = self.tlibs[guid]
            for tlib in tlibs:
                if tlib.major == majorVers:
                    return tlib
        except KeyError:
            print "WARNING: Can't lookup typelib guid %s, version %d" % (guid, majorVers)
            return None

    #
    def addLib(self, tLib):
        self.tlibs.setdefault(tLib.guid, []).append(tLib)
        self.iMan.registerInterfaces(tLib.getInterfaces())

    #
    def addTypeLibFile(self, filename):
        try:
            tl = typeLib(filename)
            self.addLib(tl)
        except OSError:
            pass

    # parse all of the system typelibs
    def addRegistryTypeLibs(self, locales=["0", "9"], arch="win32"):
        hive = _winreg.ConnectRegistry(None, _winreg.HKEY_CLASSES_ROOT)
        key = _winreg.OpenKey(hive, "Typelib")
        nLibs,d,d = _winreg.QueryInfoKey(key)
    
        #foreach typelib GUID
        for nLibNum in xrange(0, nLibs):

            #get the current typelib
            curLib = _winreg.EnumKey(key, nLibNum)
            tkey = _winreg.OpenKey(hive, "Typelib\\%s" % curLib)
            nVersions,d,d = _winreg.QueryInfoKey(tkey)
            
            #foreach version
            for nVerNum  in xrange(0, nVersions):
                try:
                    curVersion = _winreg.EnumKey(tkey, nVerNum)
                    versKey = _winreg.OpenKey(hive, "TypeLib\\%s\\%s" % (curLib, curVersion))
                    lcKey = None
    
                    #try to open each locale in our list
                    for locale in locales:
                        try:
                            lcKey = _winreg.OpenKey(hive, "Typelib\\%s\\%s\\%s\\%s" % \
                                                (curLib, curVersion, locale, arch))
                            val = _winreg.QueryValueEx(lcKey, "")[0]
    
                            #
                            tlbFile =  _winreg.ExpandEnvironmentStrings(val)
                            try:
                                tEntry = typeLib(tlbFile)
                                self.addLib(tEntry)
                            except (OSError, pythoncom.com_error):
                                pass
                            _winreg.CloseKey(lcKey)
                            break
                        except WindowsError:
                            if lcKey:
                                _winreg.CloseKey(lcKey)
                            continue
                    _winreg.CloseKey(versKey)
                except WindowsError, exc:
                    print "Unexpected end of typelib version list %s, error %s" % (guid, exc.strerror)
                    raise
    
        _winreg.CloseKey(key)

#
class simpleInterface(object):

    def __init__(self, iid, name):
        self.iid = iid
        self.name = self.entryName = name
        self.impl = None
        self.base = None

    def hierStr(self):
        return ""

    def getIFaceVTOffset(self):
        return 0

    def getVtable(self):
        return []

#simple manager for interfaces
class interfaceMan(object):

    #
    def __init__(self):
        self.ifIIDs = {}
        self.systemInterfaces = []

    #
    def checkSystemInts(self):
        broken = False
        print "Checking %d system interfaces against %d tlb interfaces" % \
                    (len(self.systemInterfaces), len(self.ifIIDs))
        for iFace in self.systemInterfaces:
            iid = iFace[0]

            if iid not in self.ifIIDs:
                print "WARNING: system interface %s %s not in our tlb list\n" % (iFace[1], iid)
                broken = True

        if broken:
            print "At least one system interface wasn't found in our TLB list\n"
            print "Please make a TLB for it\n"
    #
    def addSystemInterfaces(self):
        hive = _winreg.ConnectRegistry(None, _winreg.HKEY_CLASSES_ROOT)
        key = _winreg.OpenKey(hive, "Interface")
        count,d,d = _winreg.QueryInfoKey(key)
    
        for i in xrange(0, count):
            try:
                #get the IID + common name
                interface = _winreg.EnumKey(key, i)
                hkey = _winreg.OpenKey(hive, "Interface\\" + interface)
                try:
                    val = _winreg.QueryValueEx(hkey, "")[0]
                except WindowsError:
                    val = None
            except WindowsError, exc:
                print "Unexpected end of interface list %s, error %s" % (interface, exc.strerror)
                break
            
            iid = interface.upper()
            """
            if iid in self.ifIIDs:
                print "System interface %s (%s) already in our list" % (iid, val)
            else:
                print "NOT System interface %s (%s) already in our list" % (iid, val)
            """

            self.systemInterfaces.append((interface.upper(), val))
            siFace = simpleInterface(iid, val)
            self.registerInterface(siFace)
    
    #
    def getSysIntList(self):
        return self.systemInterfaces
    
    #
    def registerInterface(self, iFace):

        #see if we have it registered already
        iEntry = None
        try:
            iEntry = self.ifIIDs[iFace.iid]
            #print "Already registered %s %s" % (iFace.iid, iFace.entryName)
            if iEntry.iid != iFace.iid:
                print "registerInterface(%s, %s) IID conflict: (%s) vs (%s)" % \
                        (iEntry.entryName, iFace.entryName, iEntry.iid, iFace.iid)
        except KeyError:
            #print "Registered %s %s" % (iFace.iid, iFace.entryName)
            self.ifIIDs[iFace.iid] = iFace

    #
    def registerInterfaces(self, iFaces):
        for iFace in iFaces:
            self.registerInterface(iFace)

    #
    def resolveBase(self, iFace, showError = True):
        if iFace.impl:
            try:
                iFace.base = self.ifIIDs[iFace.impl]
                self.resolveBase(iFace.base)
            except KeyError:
                print ("*"*80 + "\n")*5
                print "ERROR: can'tresolve base class %s for %s" % (iFace.impl, iFace.entryName)
                print "This probably means that you need to find the idl in the SDK\n"
                print "for this interface and compile it via midl.exe\n"
                print ("*"*80 + "\n")*5
                raise NotImplementedError
        elif iFace.iid != str(pythoncom.IID_IUnknown):
            if showError:
                print "ERROR: %s (%s) has no base class" % (iFace.name, iFace.iid)
            #sys.exit(1)

    #
    def resolveHierarchies(self, showError = True):
        for ifIID, iFace in self.ifIIDs.iteritems():
            self.resolveBase(iFace, showError)

    #
    def getInterfaceByIID(self, iid):
        try:
            return self.ifIIDs[iid]
        except KeyError:
            return None

    #
    def getInterfaceByName(self, name):
        try:
            return self.ifNames[name]
        except KeyError:
            return None

    #
    def getInterfaceList(self):
        return self.ifIIDs.values()

    #
    def printHierarchies(self):
        for i in self.ifIIDs.values():
            print "%s" % i.name,
            base = i.base
            while base:
                print "-> %s" % (base.name),
                base = base.base
            sys.stdout.write("\n")

#
if __name__ == "__main__":

    iMan = interfaceMan()
    tMan = typeLibMan(iMan)
    tMan.addRegistryTypeLibs()

    for tFile in sys.argv[1:]:
        tMan.addTypeLibFile(tFile)

    #iMan.registerInterfaces(ints)
    iMan.resolveHierarchies()
    """
    ints = tMan.getInterfaces()
    print "We have %d interfaces, %d in iman\n" % (len(ints), len(iMan.getInterfaceList()))
    iMan.printHierarchies()
    for i in ints:
        iMan.resolveBase(i)
    """

    iMan.addSystemInterfaces()
    #iMan.checkSystemInts()
    """
    print "\n\nDumping typelib entries\n"
    for tlb in tMan.getLibs():
        print str(tlb)
    """
