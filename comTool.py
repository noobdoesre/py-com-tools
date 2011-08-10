#!C:\Python26\python.exe -u
import getopt
import os
import sys
import _winreg
import pefile
import time
import pythoncom
import iquery
import pyTypeLibs
import shutil

#
IID_NULL = "{00000000-0000-0000-0000-000000000000}"
CLSID_IObjectSafety = "{CB5BDC81-93C1-11CF-8F20-00805F2CD064}"
CLSID_SAFE_SCRIPT = "{7DD95801-9882-11CF-9FA9-00AA006C42C4}"
CLSID_SAFE_INIT = "{7DD95802-9882-11CF-9FA9-00AA006C42C4}"

SCRIPT_INTERFACES = [("IDispatch", "{00020400-0000-0000-C000-000000000046}"),
                        ("IDispatchEx", "{A6EF9860-C720-11D0-9337-00A0C90DCAA9}")]
PERSIST_INTERFACES = [("IPersistMemory", "{BD1AE5E0-A6AE-11CE-BD37-504200C10000}"),
                      ("IPersistFile", "{0000010B-0000-0000-C000-000000000046}"),
                      ("IPersistStorage", "{0000010A-0000-0000-C000-000000000046}"),
                      ("IPersistPropertyBag", "{37D84F60-42CB-11CE-8135-00AA004BB851}"),
                      ("IPersistPropertyBag2", "{22F55881-280B-11D0-A8A9-00A0C90C2004}"),
                      ("IPersistMoniker", "{79EAC9C9-BAF9-11CE-8C82-00AA004BA90B}"),
                      ("IPersistStream", "{00000109-0000-0000-C000-000000000046}"),
                      ("IPersistStreamInit", "{7FD52380-4E07-101B-AE2D-08002B2EC713}"),
                      ("IPersistHistory" , "{91A565C1-E38F-11D0-94BF-00A0C9055CBF}")
                      ]

#
class comInfo(object):

    #
    def __init__(self, clsid, iMan, tMan):
        self.clsid = clsid.upper()
        self.defaultInfo = None
        self.progID = None
        self.indProgID = None
        self.typeLibCLSID = None
        self.version = None
        self.InProcServer = None
        self.inprocThreadingModel = None
        self.LocalServer = None
        self.localThreadingModel = None
        self.interfaces = []
        self.LocalSupportsASLR = None
        self.InProcSupportsASLR = None
        self.tlbEntry = None
        self.iMan = iMan
        self.tMan = tMan
        self.killbit = None
        self.iobjSafety = None
        self.regSafeInit = self.regSafeScript = False
        self.tlb = None

    #
    def getBinaries(self):
        return (self.InProcServer, self.LocalServer)

    #check if the target binary supports ASLR
    def checkASLR(self):
        target = None
        try:
            if self.InProcServer:
                target = self.InProcServer
                pe = pefile.PE(self.InProcServer)
                self.InProcSupportsASLR = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)
            if self.LocalServer:
                target = self.LocalServer
                pe = pefile.PE(self.LocalServer)
                self.LocalSupportsASLR = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)
        except:
            print "Can't determine ASLR status for [%s]" % (target)

    #
    def queryInterface(self, iFace):
        try:
            iuk = iquery.iQuery(self.clsid)
        except RuntimeError, exc:
            print "ERROR: Can't create %s" % (self.clsid)
            sys.exit(1)
        try:
            return iuk.isInterfaceSupported(iFace.iid)
        except RuntimeError, exc:
            return False

    #
    def supportsInterface(self, iid):

        for interface in self.interfaces:
            if interface.iid == iid:
                return True
        return False
    
    #
    def supportsIObjectSafety(self):
        try:
            iuk = iquery.iQuery(self.clsid)
            if iuk.isInterfaceSupported(CLSID_IObjectSafety):
                return True
        except RuntimeError, exc:
            return False
        return False

    #
    def checkKillbit(self):
        hive = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
        try:
            key = _winreg.OpenKey(hive,
                    "SOFTWARE\\Microsoft\\Internet Explorer\\Activex Compatibility\\%s" % (self.clsid))
            flags = _winreg.QueryValueEx(key, "Compatibility Flags")[0]
        except WindowsError:
            flags = 0
            key = None

        if key:
            _winreg.CloseKey(key)
        return flags & 0x400

    #
    def regSafeFor(self, safe_for):
        hive = _winreg.ConnectRegistry(None, _winreg.HKEY_CLASSES_ROOT)
        try:
            key = _winreg.OpenKey(hive, "CLSID\\%s\\Implemented Categories\\%s" % \
                                        (self.clsid, safe_for))
        except WindowsError:
            return False

        _winreg.CloseKey(key)

        return True

    #
    def regSafeForInit(self):
        return self.regSafeFor(CLSID_SAFE_INIT)

    def regSafeForScript(self):
        return self.regSafeFor(CLSID_SAFE_SCRIPT)

    #
    def __str__(self):

        #basic info from the registry
        out = "+" + ("-"*78) + "+\n"
        out += "CLSID: %s\n" % self.clsid
        if self.defaultInfo:
            out += "Default Info: %s\n" % self.defaultInfo
        if self.progID:
            out += "ProgID: %s\n" % self.progID
        if self.indProgID:
            out += "IndependentProgID: %s\n" % self.indProgID
        if self.version:
            out += "Version: %s\n" % self.version
        if self.InProcServer:
            if self.InProcSupportsASLR:
                aslr = "[ASLR]"
            else:
                aslr = "[!ASLR]"
            out += "InProcServer %s, Threading Model %s %s\n" % \
                                (self.InProcServer, self.inprocThreadingModel, aslr)
        if self.LocalServer:
            if self.LocalSupportsASLR:
                aslr = "[ASLR]"
            else:
                aslr = "[!ASLR]"
            out += "LocalServer %s, Local Threading Model %s %s\n" % \
                                (self.LocalServer, self.localThreadingModel, aslr)

        #killbit + object safety
        if self.killbit:
            out += "[!]Killbit set\n"
        if self.iobjSafety:
            out += "Implements IObjectSafety:\n"
            
            #this should never fail, since we've already tested it
            try:
                iuk = iquery.iQuery(self.clsid)
            except RuntimeError, exc:
                print "ERROR: Can't create IObjectSafety for %s" % self.clsid
                sys.exit(1)

            out += "[i]Scripting support...\n"
            for i in SCRIPT_INTERFACES:
                if self.supportsInterface(i[1]):
                    try:
                        if iuk.isSafeScript(i[1]):
                            out += "\t[+]%s is Safe For Scripting\n" % i[0]
                        else:
                            out += "\t[!]%s is NOT Safe For Scripting\n" % i[0]
                    except RuntimeError, exc:
                        out += "\t[!]%s is NOT Safe For Scripting\n" % i[0]
            out += "[i]Persist support...\n"
            for i in PERSIST_INTERFACES:
                if self.supportsInterface(i[1]):
                    try:
                        if iuk.isSafeInit(i[1]):
                            out += "\t[+]%s is Safe For Initialization\n" % i[0]
                        else:
                            out += "\t[!]%s is NOT Safe For Initialization\n" % i[0]
                    except RuntimeError, exc:
                        out += "\t[!]%s is NOT Safe For Initialization\n" % i[0]
        else:
            if self.regSafeInit:
                out += "[+]Registry Safe For Initialization\n"
            else:
                out += "[+]Registry NOT Safe For Initialization\n"
            if self.regSafeScript:
                out += "[+]Registry Safe For Scripting\n"
            else:
                out += "[+]Registry NOT Safe For Scripting\n"

        #type lib information
        out += ("*"*80) + "\n"
        if self.tlb:
            out += "Typelib information:\n"
            out += "Typelib CLSID: %s\n" % (self.tlb.guid)
            if self.tlbEntry:
                out += "TypeLib: Version %d.%d Locale %s File %s\n" % \
                        (self.tlb.major, self.tlb.minor, self.tlb.lcid,
                                self.tlb.tlbFile)
            out += ("*"*80) + "\n"
        
        #supported interfaces
        if self.interfaces:

            #resolve base addr of vtable
            try:
                iuk = iquery.iQuery(self.clsid)
            except RuntimeError, exc:
                print "ERROR: Can't create interface for %s" % self.clsid
                sys.exit(1)
            
            out += "[ %d Interfaces implemented ]\n" % (len(self.interfaces))
            for iFace in self.interfaces:
                vtOffset = iuk.getIFaceVTOffset(iFace.iid)
                out += "+"*79 + "\n"
                out += "    %s (%s) - VT Offset %#x\n" % (iFace.entryName, iFace.iid, vtOffset)
                offset = 0
                for func in iFace.getVtable():
                    out += "      (%#x) %s\n" % (vtOffset + offset, str(func))
                    offset += 4

        out += "+" + ("-"*78) + "+\n"
        return out


    def read(self, checkAllInterfaces=False):

        #first read in all registry related properties
        clsid = self.clsid
        valList = [ ("CLSID\\" + clsid + "\\", "", "defaultInfo"),
                    ("CLSID\\" + clsid + "\\InProcServer32", "", "InProcServer"),
                    ("CLSID\\" + clsid + "\\InProcServer32", "ThreadingModel", "inprocThreadingModel"),
                    ("CLSID\\" + clsid + "\\LocalServer32", "", "LocalServer"),
                    ("CLSID\\" + clsid + "\\LocalServer32", "ThreadingModel", "localThreadingModel"),
                    ("CLSID\\" + clsid + "\\ProgID", "", "progID"),
                    ("CLSID\\" + clsid + "\\TypeLib", "", "typeLibCLSID"),
                    ("CLSID\\" + clsid + "\\Version", "", "version"),
                    ("CLSID\\" + clsid + "\\VersionIndependentProgID", "", "indProgID"),
                    ]

        hive = _winreg.ConnectRegistry(None, _winreg.HKEY_CLASSES_ROOT)
    
        #
        for vals in valList:
            try:
                #
                curKey =  vals[0]
                curVal = vals[1]
                curProp = vals[2]
                key = None
                key = _winreg.OpenKey(hive, curKey)
                val = _winreg.QueryValueEx(key, curVal)
                setattr(self, curProp, val[0])
                _winreg.CloseKey(key)
            except WindowsError, exc:
                try:
                    if key:
                        _winreg.CloseKey(key)
                except WindowsError:
                    pass

        # parse out the version number for use in finding typelib
        if self.version:
            major, minor = self.version.split(".")
            self.majorVers = int(major)
            self.minorVers = int(minor)
        
        #expand any environment variables in the path to binaries
        if self.InProcServer:
            self.InProcServer = _winreg.ExpandEnvironmentStrings(self.InProcServer)
        if self.LocalServer:
            self.LocalServer = _winreg.ExpandEnvironmentStrings(self.LocalServer)
        
        self.checkASLR()

        #parse the typelib, and add any new interfaces we can discover from it
        if self.version and self.typeLibCLSID:
            self.typeLibCLSID = self.typeLibCLSID.upper()
            self.tlb = self.tMan.getLib(self.typeLibCLSID, self.majorVers)

            if not self.tlb:
                pass
                """
                print "WARNING: Can't find typelib file for %s major %d\n%s" % (self.typeLibCLSID,
                                                self.majorVers, str(self))
                print "\n\nDumping typelib entries\n"
                for tlb in self.tMan.getLibs():
                    print str(tlb)
                sys.exit(1)
                """

        #make sure we can instantiate it
        try:
            iuk = iquery.iQuery(self.clsid)
            canMake = True
            del iuk
        except RuntimeError, exc:
            canMake = False

        #
        if canMake and checkAllInterfaces:
            for iFace in self.iMan.getInterfaceList():
                if self.queryInterface(iFace):
                    self.interfaces.append(iFace)
                    self.iMan.resolveBase(iFace)
        elif canMake:
            #just check scripting/initialization interfaces
            for i in SCRIPT_INTERFACES + PERSIST_INTERFACES:
                iFace = self.iMan.getInterfaceByIID(i[1])
                if not iFace:
                    print "ERROR: Can't resolve %s %s" % (i[0], i[1])
                    sys.exit(1)
                if self.queryInterface(iFace):
                    self.interfaces.append(iFace)
                    self.iMan.resolveBase(iFace)

        #get safety options
        self.killbit = self.checkKillbit()
        self.iobjSafety = self.supportsIObjectSafety()
        if not self.iobjSafety:
            self.regSafeInit = self.regSafeForInit()
            self.regSafeScript = self.regSafeForScript()


# open up the registry and read the IE 'whitelist' controls
def getAxWhiteList():
    clsidList = []
    hive = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
    key = _winreg.OpenKey(hive, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\PreApproved')
    count,d,d = _winreg.QueryInfoKey(key)

    for i in xrange(0, count):
        try:
            clsid = _winreg.EnumKey(key, i)
            clsidList.append(clsid)
        except WindowsError:
            print "Unexpected end of whitelist registry key"
            raise

    _winreg.CloseKey(key)
    return clsidList

# open up the registry and read in all supported COM controls
def getCOMList():
    clsidList = []
    hive = _winreg.ConnectRegistry(None, _winreg.HKEY_CLASSES_ROOT)
    key = _winreg.OpenKey(hive, r'CLSID')
    count,d,d = _winreg.QueryInfoKey(key)

    for i in xrange(0, count):
        try:
            clsid = _winreg.EnumKey(key, i)
            clsidList.append(clsid)
        except WindowsError:
            print "Unexpected end of CLSID registry key"
            raise

    _winreg.CloseKey(key)
    return clsidList

#
def getCOMDetails(clsids, iMan, tMan):

    hive = _winreg.ConnectRegistry(None, _winreg.HKEY_CLASSES_ROOT)
    comList = []
    for clsid in clsids:
    
        # test to see if this control is actually installed on the system
        try:
            key = _winreg.OpenKey(hive, "CLSID\\" + clsid)
            info = _winreg.QueryInfoKey(key)
        except WindowsError, exc:
            continue

        control = comInfo(clsid, iMan, tMan)
        control.read()
        comList.append(control)

    return comList

#
def checkASLR(binary):
    pe = pefile.PE(binary)
    return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)

#
def showCOMASLR(clsids, iMan, tMan):

    hive = _winreg.ConnectRegistry(None, _winreg.HKEY_CLASSES_ROOT)
    for clsid in clsids:
    
        # test to see if this control is actually installed on the system
        try:
            key = _winreg.OpenKey(hive, "CLSID\\" + clsid + "\\InProcServer32")
            val = _winreg.QueryValueEx(key, "")[0]
            _winreg.CloseKey(key)
            try:
                if not checkASLR(val):
                    print "%s (%s) doesn't support ASLR" % (val, clsid)
                    control = comInfo(clsid, iMan, tMan)
                    control.read(True)
                    print str(control)
            except:
                pass
        except WindowsError, exc:
            continue

#
def queryCLSID(clsid, tMan, iMan):

    # test to see if this control is actually installed on the system
    hive = _winreg.ConnectRegistry(None, _winreg.HKEY_CLASSES_ROOT)
    try:
        key = _winreg.OpenKey(hive, "CLSID\\" + clsid)
        info = _winreg.QueryInfoKey(key)
    except WindowsError, exc:
        print "CLSID %s does not exist in registry" % (clsid)

    control = comInfo(clsid, iMan, tMan)
    control.read(True)
    print str(control)

#
def queryFile(comFile, tMan, iMan, coClassCLSID):

    class tmpCoClass(object):
        def __init__(self, name, iid):
            self.iid = iid
            self.name = self.entryName = name

    if not os.access(comFile, os.R_OK|os.X_OK):
        print "Bad file permissions on %s, can't RX" % (comFile)
        return
    
    print "Querying %s" % comFile

    try:
        tlb = pyTypeLibs.typeLib(comFile)
        tMan.addLib(tlb)
        classes = tlb.getClasses()
    except OSError, exc:
        if not coClassCLSID:
            print "%s has no typelib, but we need a CLSID to create an instance" % comFile
            print "Try passing the -C argument with a clsid to instantiate"
            sys.exit(1)
        else:
            tmpClass = tmpCoClass("tmpClass", coClassCLSID)
            print "Using CLSID %s to instantiate" % (coClassCLSID)
            classes = [tmpClass]
 
    #
    if coClassCLSID:
        tmpClass = tmpCoClass("obj", coClassCLSID)
        print "Using CLSID %s to instantiate" % (coClassCLSID)
        classes = [tmpClass]

    #
    for coclass in classes:
        
        #try and instantiate each coclass we find
        try:
            start = time.time()
            iuk = iquery.iQuery()
            if iuk.coCreateUnknown(comFile, coclass.iid):
                print "Class %s (%s)" % (coclass.entryName, coclass.iid)
                #raw_input()
                del iuk
            else:
                print "Failed to CoCreate class %s %s" % (coclass.entryName, coClass.iid)
                continue
            end = time.time()
            #print "Took %f seconds to create unknown" % (end - start)

            #
            for iFace in iMan.getInterfaceList():

                #any exception caught by the outside try{}
                iuk = iquery.iQuery()
                if not iuk.coCreateUnknown(comFile, coclass.iid):
                    break
                
                #
                start = time.time()
                try:
                    if iuk.isInterfaceSupported(iFace.iid):
                        iMan.resolveBase(iFace)
                        print "  Interface %s %s" % (iFace.entryName, iFace.iid)
                        print "    Inheritance hierarchy: %s" % (iFace.hierStr())
                        vtOffset = iuk.getIFaceVTOffset(iFace.iid)
                        print "      %s - VT Offset %#x" % (iFace.entryName, vtOffset)
                        offset = 0
                        for func in iFace.getVtable():
                            print "      (%#x) %s" % (vtOffset + offset, str(func))
                            offset += 4
                    else:
                        #print "%s (%s) not supported" % (iFace.iid, iFace.entryName)
                        pass
                except RuntimeError, exc:
                    #print "%s (%s) not supported (EXC)" % (iFace.iid, iFace.entryName)
                    pass

                end = time.time()
                #print "Took %f seconds to Query for %s" % (end - start, iFace.entryName)
                del iuk

        except RuntimeError, exc:

            #don't error if it's coclass that claims to not be creatable
            if not isinstance(coclass, pyTypeLibs.tCoClass) or coclass.canCreate():
                print "Failed to CoCreate class %s %s, %s" % (coclass.entryName, coclass.iid, str(exc))
                print("If LoadLibrary() failed, it may be because the DLL tried load a resource\n"
                        "DLL that is based on the current module name. msxml3.dll tries to do this\n"
                        "when it tries to load msxml3r.dll\n")

#
DUMP_WHITELIST = 1
DUMP_FILE = 2
DUMP_ALL_COM_ASLR = 3
DUMP_TYPELIBS = 4
DUMP_CLSID = 5
DUMP_TYPELIB = 6

#
def usage(prog):
    print "Usage %s [ -f investigate dll/ocx/exe ] [ -x dump activex whitelist controls ]\n" \
            "\t[ -t directory with typelibs ] [ -c dump installed clsid (must be regsrv32'd) ]\n" \
            "\t[ -a show ASLR status for all COM objects ] [ -l dump all typelibs ]\n" \
            "\t[ -b <typelib file> to dump ] [ -C coclass clsid (with -f if no tlb) ]\n" \
            "\t[ -p <dir> copy all binaries from whitelist controls into dir (use with -x) ]\n" \
            "\nExamples:\n" \
            "  Dump all COM classes found in the TLB of somBinary:\n" \
            "\t%s -f somBinary -t sdk-tlbs\n" \
            "\n  Dump COM class CLSID from somBinary:\n" \
            "  This option is needed when the binary has no TLB and is not a registered COM object\n" \
            "\t%s -f somBinary -t sdk-tlbs -C coclass CLSID\n" \
            "\n  Dump basic info for all controls on the whitelist\n" \
            "  This is NOT an exhaustive list of all interfaces, just scripting/initialization.\n" \
            "\t%s -x -t sdk-tlbs\n" \
            % (prog, prog, prog, prog)
    sys.exit(1)

#
if __name__ == "__main__":
    mode = -1
    copyDir = tlbDir = coClassCLSID = None

    #parse arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], "t:f:axlc:b:C:p:")
    except getopt.GetoptError, err:
        print str(err)
        usage(sys.argv[0])

    for o,a in opts:
        if o == "-l":
            mode = DUMP_TYPELIBS
        elif o == "-C":
            coClassCLSID = a
        elif o == "-p":
            copyDir =a
        elif o == "-f":
            mode = DUMP_FILE
            comFile = a
        elif o == "-b":
            mode = DUMP_TYPELIB
            tlbFile = a
        elif o == "-c":
            mode = DUMP_CLSID
            targetCLSID = a
        elif o == "-x":
            mode = DUMP_WHITELIST
        elif o == "-a":
            mode = DUMP_ALL_COM_ASLR
        elif o == "-t":
            tlbDir = a
        else:
            print "bad in opts %s %s" % (o, a)
            usage(sys.argv[0])
    
    if mode == -1:
        usage(sys.argv[0])

    pythoncom.CoInitialize()

    #initialize the interface/typelib managers, add all registry defined interfaces/typelibs
    iMan = pyTypeLibs.interfaceMan()
    tMan = pyTypeLibs.typeLibMan(iMan)
    tMan.addRegistryTypeLibs()

    #
    if tlbDir:
        for f in os.listdir(tlbDir):
            tFile = os.path.join(tlbDir, f)
            tMan.addTypeLibFile(tFile)
    else:
        print "WARNING: You didn't add any TLB files?\nWon't be able to dump VTABLEs"

    iMan.addSystemInterfaces()
    
    #print "Have %d registry/file interfaces" % (len(tMan.getInterfaces()))
    #iMan.checkSystemInts()
    
    #
    if mode == DUMP_TYPELIB:
        tlb = pyTypeLibs.typeLib(tlbFile)
        for i in tlb.getInterfaces():
            iMan.resolveBase(i)
        print str(tlb)
    elif mode == DUMP_TYPELIBS:
        print "Dumping system typelibs (HKCR\\Typelibs)..\n"

        #we use the interface manager to resolve the inheritance hierarchy
        #this results in some duplicated work
        #iMan.registerInterfaces(tMan.getInterfaces())
        iMan.resolveHierarchies()
        iMan.printHierarchies()
        for i in tMan.getInterfaces():
            iMan.resolveBase(i)

        for tlb in tMan.getLibs():
            print str(tlb)
    elif mode == DUMP_FILE:
        queryFile(comFile, tMan, iMan, coClassCLSID)
    elif mode == DUMP_CLSID:
        queryCLSID(targetCLSID, tMan, iMan)
    elif mode == DUMP_WHITELIST:
        clsids = getAxWhiteList()
        axList = getCOMDetails(clsids, iMan, tMan)

        #
        print "[+]There are %d installed controls on the whitelist\n" % (len(axList))
        for ax in axList:
            print "%s" % (ax)
            if copyDir:
                inProc, local = ax.getBinaries()
                if inProc:
                    try:
                        shutil.copyfile(inProc, copyDir + os.sep + os.path.basename(inProc))
                    except IOError as (errno, err):
                        print "Error (%d, %s) copying file %s" % (errno, err, inProc)
                if local:
                    try:
                        shutil.copyfile(local, copyDir + os.sep + os.path.basename(local))
                    except IOError as (errno, err):
                        print "Error (%d, %s) copying file %s" % (errno, err, local)


        print "####################################################\n"*4
    elif mode == DUMP_ALL_COM_ASLR:

        clsids = getCOMList()
        showCOMASLR(clsids, iMan, tMan)
    else:
        print "Invalid mode? %d" % mode
        sys.exit(1)

    sys.exit(0)
