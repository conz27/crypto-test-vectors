from Crypto.Cipher import AES

from array import *
from ecc import *

# Uncomment the following to obtain different values every time this script is run
# Using version 1 of PRNG (Python 3 using Python 2 seed() impl)
seed(333, version=1)


def f_k_int_x(k, x):
    aes_obj = AES.new(k.decode('hex'), AES.MODE_ECB)
    s = ""
    for i in range(1, 4):
        print("x+" + str(i) + ": Input to AES block " + str(i) + " encryption (128 bits):")
        xpi = "{0:032X}".format(x + i)
        print("0x" + xpi)
        cArrayDef("[be]", "xp" + str(i), int(xpi, 16), 128 / 8, radix_8, False);
        print(os.linesep)

        print("AES_k(x+" + str(i) + "): Output of AES block " + str(i) + " encryption (128 bits):")
        aes_xpi = aes_obj.encrypt(xpi.decode('hex')).encode('hex')
        print("0x" + aes_xpi.upper())
        cArrayDef("[be]", "aes_xp" + str(i), int(aes_xpi, 16), 128 / 8, radix_8, False);
        print(os.linesep)

        print("AES_k(x+" + str(i) + ") XOR (x+" + str(i) + "): block " + str(i) + " (128 bits):")
        blki_int = int(xpi, 16) ^ int(aes_xpi, 16)
        blki = "{0:032X}".format(blki_int)
        print("0x" + blki)
        cArrayDef("[be]", "block_" + str(i), blki_int, 128 / 8, radix_8, False);
        print(os.linesep)

        s += blki

    return s.upper()


radix_256 = 2 ** 256
radix_128 = 2 ** 128
radix_32 = 2 ** 32
radix_16 = 2 ** 16
radix_8 = 2 ** 8

genP256 = ECPoint(secp256r1.gx, secp256r1.gy, secp256r1)

a = randint(1, genP256.ecc.n - 1)
A = a * genP256
h = randint(1, genP256.ecc.n - 1)
H = h * genP256

ck = "{0:032X}".format(getrandbits(128))
ek = "{0:032X}".format(getrandbits(128))
i = randint(1, radix_32)
j = randint(1, 20)

x_cert = (i * radix_32 + j) * radix_32
x_enc = (((radix_32 - 1) * radix_32 + i) * radix_32 + j) * radix_32

print("""
Test vectors for Butterfly Expansion Function
=============================================
""")

print("\"le\": little-endian")
print("\"be\": big-endian")

print("Curve: NISTp256")
print("---------------")

print("i (32 bits):")
print(Hex(i, radix_32) + os.linesep)

print("j (in range [1,20], padded to 32 bits) =")
print(Hex(j, radix_32) + os.linesep)

print("Expanding Certificate key pair (a,A)")
print("------------------------------------")

print("ck: AES key (128 bits, randomly generated):")
print("0x" + ck)
cArrayDef("[be]", "ck", int(ck, 16), 128 / 8, radix_8, False)
print(os.linesep)

print("a: Signing seed private key (256 bits):")
print(Hex(a, radix_256))
cArrayDef("[le]", "a", a, 256 / 32, radix_32, True);
print(os.linesep)

print("A: Signing seed public key (2*256 bits):")
print(A)
print("[le] A = {")
cArrayDef("", "", A.x, 8, radix_32);
print()
cArrayDef("", "", A.y, 8, radix_32);
print()
print("}" + os.linesep)

print("x_cert: Expansion function input for Certificate keys (128 bits):")
print(Hex(x_cert, radix_128) + os.linesep)

f_k_int_x_cert = f_k_int_x(ck, x_cert)
print("f_k^{int}(x) = block1 || block2 || block3 (384 bits):")
print("0x" + f_k_int_x_cert)
cArrayDef("[be]", "f_k_int_x_cert", int(f_k_int_x_cert, 16), 384 / 8, radix_8, False)
print(os.linesep)

print("f_k(x) = f_k^{int}(x) mod l, where l is the order of the group of points on the curve (256 bits):")
f_k_x_cert = int(f_k_int_x_cert, 16) % genP256.ecc.n
print(Hex(f_k_x_cert, radix_256))
cArrayDef("[le]", "f_k_x_cert", f_k_x_cert, 256 / 32, radix_32, True)
print(os.linesep)

print("a + f_k(x_cert) mod l: Expanded private key (256 bits)")
a_exp = (a + f_k_x_cert) % genP256.ecc.n
print(Hex(a_exp, radix_256))
cArrayDef("[le]", "a_exp", a_exp, 256 / 32, radix_32, True)
print(os.linesep)

print("A + f_k(x_cert)*G_P256 mod l: Expanded public key (256 bits)")
A_exp = A + f_k_x_cert * genP256
print(A_exp)
print("[le] A_exp = {")
cArrayDef("", "", A_exp.x, 8, radix_32);
print()
cArrayDef("", "", A_exp.y, 8, radix_32);
print()
print("}" + os.linesep)

assert a_exp * genP256 == A_exp, "error in certificate key expansion"
print("SUCCESS: Verified that expanded certificate private and public keys form a key pair" + os.linesep)

print("Expanding Encryption key pair (h,H)")
print("-----------------------------------")

print("ek: AES key (128 bits, randomly generated):")
print("0x" + ek)
cArrayDef("[be]", "ek", int(ek, 16), 128 / 8, radix_8, False)
print(os.linesep)

print("h: Signing seed private key (256 bits):")
print(Hex(h, radix_256))
cArrayDef("[le]", "h", h, 256 / 32, radix_32, True);
print(os.linesep)

print("H: Signing seed public key (2*256 bits):")
print(H)
print("[le] H = {")
cArrayDef("", "", H.x, 8, radix_32)
print()
cArrayDef("", "", H.y, 8, radix_32)
print()
print("}" + os.linesep)

print("x_enc: Expansion function input for Encryption keys (128 bits):")
print(Hex(x_enc, radix_128) + os.linesep)

f_k_int_x_enc = f_k_int_x(ek, x_enc)
print("f_k^{int}(x) = block1 || block2 || block3 (384 bits):")
print("0x" + f_k_int_x_enc)
cArrayDef("[be]", "f_k_int_x_enc", int(f_k_int_x_enc, 16), 384 / 8, radix_8, False)
print(os.linesep)

print("f_k(x) = f_k^{int}(x) mod l, where l is the order of the group of points on the curve (256 bits):")
f_k_x_enc = int(f_k_int_x_enc, 16) % genP256.ecc.n
print(Hex(f_k_x_enc, radix_256))
cArrayDef("[le]", "f_k_x_enc", f_k_x_enc, 256 / 32, radix_32, True)
print(os.linesep)

print("h + f_k(x_enc) mod l: Expanded private key (256 bits)")
h_exp = (h + f_k_x_enc) % genP256.ecc.n
print(Hex(h_exp, radix_256))
cArrayDef("[le]", "h_exp", h_exp, 256 / 32, radix_32, True)
print(os.linesep)

print("H + f_k(x_enc)*G_P256 mod l: Expanded public key (256 bits)")
H_exp = H + f_k_x_enc * genP256
print(H_exp)
print("[le] H_exp = {")
cArrayDef("", "", H_exp.x, 8, radix_32)
print()
cArrayDef("", "", H_exp.y, 8, radix_32)
print()
print("}" + os.linesep)

assert h_exp * genP256 == H_exp, "error in encryption key expansion"
print("SUCCESS: Verified that expanded encryption private and public keys form a key pair" + os.linesep)
