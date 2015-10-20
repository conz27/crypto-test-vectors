def Hex(n, radix=0):
    """Converts n to a hex string.
       If radix is not 0, pads to the max number of characters for digits modulo the radix.
       Uses capital letters, and no trailing L.
    """
    if n < 0:
        signum = "-"
    else:
        signum = ""

    nh = hex(abs(n))[2:]

    if nh.find("L") >= 0:
        nh = nh[:-1]

    pad = (len(bin(radix)))/4  # -3 for the 0b[01], but then +3 for the round up.

    if pad >= len(nh):
        pad -= len(nh)
    else:
        pad = 0

    return signum + "0x" + int(pad) * "0" + nh.upper()


def int2lelist(n, radix, listlen=0):
    """Converts n to a little-endian list of length at least listlen in the given radix.
    """
    if n < 0:
        n = -n
    elif n == 0:
       nlist = [0]
    else:
       nlist = []

    while n:
        nlist.append(int(n % radix))
        n = n // radix

    while len(nlist) < listlen:
        nlist.append(0)

    return nlist[:]


def belist2int(nlist, radix):
    """Converts n from a big-endian list in the given radix to an integer.
    """
    n = 0
    for ndigit in nlist:
        n *= radix
        n += ndigit

    return n


def int2belist(n, radix, listlen=0):
    """Converts n to a big-endian list of length at least listlen in the given radix.
    """
    nlist = int2lelist(n, radix, listlen)
    nlist.reverse()

    return nlist[:]


def lelist2int(nlist, radix):
    """Converts n from a little-endian list in the given radix to an integer.
    """
    nlist_rev = nlist[:]
    nlist_rev.reverse()

    return belist2int(nlist_rev, radix)
