#!/cygdrive/c/Python27/python.exe
import sys
import pythoncom
import iquery

if len(sys.argv) < 2:
    print "Usage %s < clsid > < iid >" % sys.argv[0]
    sys.exit(1)

clsid = sys.argv[1]
iid = sys.argv[2]

#
try:
    iuk = iquery.iQuery(clsid)
except RuntimeError, exc:
    print "Failed to create %s" % (clsid)
    sys.exit(1)

try:
    if iuk.isInterfaceSupported(iid):
        print "%s supports %s" % (clsid, iid)
    else:
        print "%s DOES NOT support %s" % (clsid, iid)
except RuntimeError, exc:
    print "%s DOES NOT support %s (%s)" % (clsid, iid, str(exc))
