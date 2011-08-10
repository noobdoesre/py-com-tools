import pythoncom
import iquery
import pyTypeLibs
import idc
import idaapi

#
def queryFile(comFile, tMan, iMan, coClassCLSID=None, coClassName=None):

    success = False
    imgBase = idaapi.get_imagebase()

    class tmpCoClass(object):
        def __init__(self, name, iid):
            self.iid = iid
            self.name = self.entryName = coClassName

    if not os.access(comFile, os.R_OK|os.X_OK):
        print "Bad file permissions on %s, can't RX" % (comFile)
        return False

    try:
        tlb = pyTypeLibs.typeLib(comFile)
        tMan.addLib(tlb)
        classes = tlb.getClasses()
    except OSError:
        if not coClassCLSID:
            print "%s has no typelib, but we need a CLSID to create an instance" % comFile
            print "Try passing the -C argument with a clsid to instantiate"
            return False
        else:
            tmpClass = tmpCoClass("obj", coClassCLSID)
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
            iuk = iquery.iQuery()
            if iuk.coCreateUnknown(comFile, coclass.iid):
                success = True
                print "Class %s (%s)" % (coclass.entryName, coclass.iid)
                del iuk
            else:
                print "Failed to CoCreate class %s %s" % (coclass.entryName, coClass.iid)
                continue

            #
            for iFace in iMan.getInterfaceList():

                #any exception caught by the outside try{}
                iuk = iquery.iQuery()
                if not iuk.coCreateUnknown(comFile, coclass.iid):
                    break
                
                #
                try:
                    if iuk.isInterfaceSupported(iFace.iid):
                        iMan.resolveBase(iFace)
                        print "  Interface %s %s" % (iFace.entryName, iFace.iid)
                        print "    Inheritance hierarchy: %s" % (iFace.hierStr())
                        vtOffset = imgBase + iuk.getIFaceVTOffset(iFace.iid)
                        iName = coclass.entryName + "::" + iFace.entryName
                        if not idaapi.set_name(int(vtOffset), str(iName)):
                            print "ERROR:Failed to set interface name, (%#x, %s)" % (vtOffset, iName)
                        print "    %s - VT addr %#x" % (iFace.entryName, vtOffset)
                        offset = 0
                        for func in iFace.getVtable():
                            fName = iName + "::" + func.name
                            fAddr = idc.Dword(vtOffset + offset)
                            if not idaapi.set_name(int(fAddr), str(fName)):
                                print "ERROR:Failed to set function name, (%#x, %s)" % (fAddr, fName)
                                break
                            #print "      (%#x) %s" % (vtOffset + offset, str(func))
                            offset += 4
                    else:
                        #print "%s (%s) not supported" % (iFace.iid, iFace.entryName)
                        pass
                except RuntimeError, exc:
                    #print "EXC %s" % (exc)
                    #print "%s (%s) not supported (EXC)" % (iFace.iid, iFace.entryName)
                    pass

                del iuk

        except RuntimeError, exc:
            if not isinstance(coclass, pyTypeLibs.tCoClass) or coclass.canCreate():
                print "INFO:Failed to CoCreate class %s %s, %s" % (coclass.entryName, coclass.iid, str(exc))
                print("If LoadLibrary() failed, it may be because the DLL tried load a resource\n"
                        "DLL that is based on the current module name. msxml3.dll tries to do this\n"
                        "when it tries to load msxml3r.dll\n")

    return success

#main
#set the maximum name length or we'll get failures in set_name()
idc.SetLongPrm(idc.INF_NAMELEN, 500)
pythoncom.CoInitialize()
iMan = pyTypeLibs.interfaceMan()
tMan = pyTypeLibs.typeLibMan(iMan)
tMan.addRegistryTypeLibs()
tlbDir = idaapi.idadir("python") + os.sep + "sdk-tlbs"

for f in os.listdir(tlbDir):
    tFile = os.path.join(tlbDir, f)
    tMan.addTypeLibFile(tFile)

iMan.addSystemInterfaces()

inFile = idaapi.get_input_file_path()
if not queryFile(inFile, tMan, iMan):
    clsid = idc.AskStr(None, "Enter a CLSID to instantiate?")
    name = idc.AskStr("tmpCoClass", "Now give it a name")
    if clsid and clsid != "":
        queryFile(inFile, tMan, iMan, clsid, name)
