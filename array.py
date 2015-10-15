from __future__ import print_function
from radix import *

#------------------------------------------------------------------------
#
# Output the definition of an array from a list:
#
def cArrayDefFromList(arraytype, arrayname, arraylist, arrayradix=2**32):
    if arrayname != "":
        arrayelems = "[" + str(len(arraylist)) + "] = "
        print(arraytype, arrayname + arrayelems)

    print("{ ", end="")
    for i in range(0,len(arraylist)-1):
        if i and i % 16 == 0:
            print()
            print("  ", end="")
        print(Hex(arraylist[i], arrayradix) + ", ", end="")
    i += 1
    if i and i % 16 == 0:
        print()
        print("  ", end="")
    print(Hex(arraylist[i], arrayradix) + " }", end="")

#
# Output the definition of an array (from a value):
#
def cArrayDef(arraytype, arrayname, arrayvalue, arraylen=0, arrayradix=2**32, littleendian=True):
    if littleendian:
        arraylist = int2lelist(arrayvalue, arrayradix, arraylen)
    else:
        arraylist = int2belist(arrayvalue, arrayradix, arraylen)

    cArrayDefFromList(arraytype, arrayname, arraylist, arrayradix)


