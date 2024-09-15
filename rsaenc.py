# Includes

import random
import math
import os
import json
import hashlib

# Flags

kp = 1
iw = 0

# Setting up hashlib for digital signatures

h = hashlib.new("SHA256")

# Helper Functions

def is_prime(number):
    if number < 2:
        False

    for i in range(2, number//2+1):
        if number % i == 0:
            return False
        
    return True

def generate_prime(minval, maxval):
    prime = random.randint(minval, maxval)

    while not is_prime(prime):
        prime = random.randint(minval, maxval)

    return prime

def mod_inv(e, phi):
    for d in range(3, phi):
        if (d*e)%phi == 1:
            return d
        
    raise ValueError("\n[ERROR] - Mod Inverse does not exist :(")

# Initial Algorithm

def inalg():
    global phi
    p, q = generate_prime(1000, 5000), generate_prime(1000, 5000)

    while p == q:
       q = generate_prime(1000, 5000)

    n = str(p*q) + "\n"
    potlpn = open("./.keypair/id_rsa.pub", "w")
    potlpn.write("  ----ID RSA----\n")
    potlpn.write("----Public Key----\n\n")
    potlpn.write(n)
    potlpn.close()

    phi = (p-1)*(q-1)

# Public Key Generation

def genpubkey():
    e = random.randint(3, phi-1)

    while math.gcd(e, phi) != 1:
        e = random.randint(3, phi-1)

    pubkeyw = open("./.keypair/id_rsa.pub", "a")
    pubkeyw.write(str(e))
    pubkeyw.close()


# Private Key Generation

def genprikey():
    print("\n[Warning] - !!! Don't share your private key with anyone if leaked can cause security breaches !!!")
    
    d = mod_inv(pubkeyraw, phi)

    prikeyw = open("./.keypair/id_rsa", "w")
    prikeyw.write("  ----ID  RSA----\n")
    prikeyw.write("----Private Key----\n")
    prikeyw.write("\n[Warning] - Sharing this file will lead to breach of encryption and spoofed signatures\n\n")
    prikeyw.write(str(d))
    prikeyw.close()

# Encryption

def enc():
    if not os.path.isdir("./enc"):
        os.mkdir("./enc")

    pubkeyepat = input("Enter path for user public key file : ")
    pubkeye = open(pubkeyepat, "r")
    pubkeyeraw = int(pubkeye.read().splitlines()[4])
    pubkeye.close()

    pubkeye = open(pubkeyepat, "r")
    ne = int(pubkeye.read().splitlines()[3])
    pubkeye.close()

    msg = input("Enter Message : ")
    ascmsg = [ord(ch) for ch in msg]
    cip = [pow(ch, pubkeyeraw, ne) for ch in ascmsg]

    print("\n[INFO] - The encrypted messages will be saved in enc directory within current working directory")
    cname = input("Do you want to name the cipher file (Y or N) : ")
    if cname == "Y" or cname == "y":
        fname = input("Name of cipher file : ")
        cfile = "./enc/" + fname
        cipher = open(cfile, "w")
        jcip = json.dumps(cip)
        cipher.write(jcip)
        cipher.close()
    elif cname == "N" or cname == "n":
        pname = "./enc/cipher"
        cfile = "./enc/cipher"
        appendent = "0"
        while iw == 0:
            if not os.path.isfile(pname):
                cipher = open(pname, "w")
                jcip = json.dumps(cip)
                cipher.write(jcip)
                cipher.close()
                break
            else:
                iapp = int(appendent)
                iapp += 1
                appendent = str(iapp)
                pname = cfile + appendent
    else:
        raise ValueError("\n[ERROR] - Invalid input please try again :< ")
    
    anss = input("Do you also want to generate a signature (Y or N) : ")
    if kp == 0:
            print("\n[ERROR] - Can't generate a signature missing keypair")
    elif anss == "Y" or anss == "y":
        h.update(msg.encode())
        hashmsg = h.digest()
        sig = [pow(ch, prikeyraw, n) for ch in hashmsg]
        sign = open(cfile, "a")
        jsig = json.dumps(sig)
        sign.write("\n" + jsig)
        sign.close()
    elif anss == "N" or anss == "n":
        print("\n[INFO] - Signature not generated :|")
    else:
        raise ValueError("\n[ERROR] - Invalid input please try again :< ")


# Decryption

def dec():
    if not os.path.isdir("./.dec"):
        os.mkdir("./.dec")

    if kp == 0:
            print("\n[ERROR] - Can't decrypt missing key pair :/")
    
    cipfp = input("Enter the path for cipher file : ")
    cipf = open(cipfp, "r")
    cip = cipf.read().splitlines()[0]
    cipf.close()
    cip = json.loads(cip)
    
    msgenc = [pow(num, prikeyraw, n) for num in cip]
    dmsg = "".join(chr(ch) for ch in msgenc)
    print("\nDecrypted Message : " + dmsg)

    print("[INFO] - The decrypted messages will be saved in .dec directory within current working directory")
    mname = input("Do you want to name the message file (Y or N) : ")
    if mname == "Y" or mname == "y":
        fname = input("Name of cipher file : ")
        mfile = "./.dec/" + fname
        message = open(mfile, "w")
        message.write(dmsg)
        message.close()
    elif mname == "N" or mname == "n":
        pname = "./.dec/message"
        mfile = "./.dec/message"
        appendent = "0"
        while iw == 0:
            if not os.path.isfile(pname):
                message = open(pname, "w")
                message.write(dmsg)
                message.close()
                break
            else:
                iapp = int(appendent)
                iapp += 1
                appendent = str(iapp)
                pname = mfile + appendent
    else:
        raise ValueError("\n[ERROR] - Invalid input please try again :< ")
    
    sigf = open(cipfp, "r")

    try:
        sig = sigf.read().splitlines()[1]
        sigf.close()
        sig = json.loads(sig)

        pubkeyepat = input("Enter path for user public key file : ")
        pubkeye = open(pubkeyepat, "r")
        pubkeyeraw = int(pubkeye.read().splitlines()[4])
        pubkeye.close()

        pubkeye = open(pubkeyepat, "r")
        ne = int(pubkeye.read().splitlines()[3])
        pubkeye.close()

        sigenc = [pow(hexnum, pubkeyeraw, ne) for hexnum in sig]
        dsig = bytes(sigenc)

        h.update(dmsg.encode())
        hmsg = h.digest()

        if hmsg == dsig:
            print("[INFO] - Signature Verified :)")
        else:
            print("[ERROR] - Invalid Signature :?")
    except IndexError:
        print("[WARNING] - The cipher file does not include signature")

# Genrating Key Pair

print("\n[Warning] - !!! Genrating a key pair will overwrite the old ones so if a key pair already exist in current working directory or specified directory make sure to back them up !!!")
print("\n[INFO] - The key pair will be generated in .keypair directory within current working directory")
anskp = input("Do you want to generate a key pair (Y or N) : ")

if anskp == "Y" or anskp == "y":
    kp = 1

    if not os.path.isdir("./.keypair"):
        os.mkdir("./.keypair")

    inalg()
    
    if not os.path.isdir("./enc"):
        os.mkdir("./enc")

    if not os.path.isdir("./.dec"):
        os.mkdir("./.dec")

    genpubkey()
    pubkey = open("./.keypair/id_rsa.pub", "r")
    n = int(pubkey.read().splitlines()[3])
    pubkey.close()

    pubkey = open("./.keypair/id_rsa.pub", "r")
    pubkeyraw = int(pubkey.read().splitlines()[4])
    pubkey.close()

    genprikey()
    prikey = open("./.keypair/id_rsa", "r")
    prikeyraw = int(prikey.read().splitlines()[5])
    prikey.close()
elif anskp == "N" or anskp == "n":
    ansd = input("Do you want to import key pair from specific directory or don't want to import key pair (Default : Current Working Directory) || (S or N): ")

    if ansd == "S" or ansd == "s":
        sdir = input("Enter path to .keypair folder : ")
        sdirpri = sdir + "/.keypair/id_rsa"
        sdirpub = sdir + "/.keypair/id_rsa.pub"

        if os.path.isfile(sdirpri) and os.path.isfile(sdirpub):
            pubkey = open(sdirpub, "r")
            n = int(pubkey.read().splitlines()[3])
            pubkey.close()

            pubkey = open(sdirpub, "r")
            pubkeyraw = int(pubkey.read().splitlines()[4])
            pubkey.close()

            prikey = open(sdirpri, "r")
            prikeyraw = int(prikey.read().splitlines()[5])
            prikey.close()
        else:
            kp = 0
            print("\n[INFO] - The key pair is not avalaible or key pair is corrupted")
    elif ansd == "N" or ansd == "n":
        print("\n[INFO] - Key pair is not imported\n")
    else:
        if os.path.isfile("./.keypair/id_rsa") and os.path.isfile("./.keypair/id_rsa.pub"):
            pubkey = open("./.keypair/id_rsa.pub", "r")
            n = int(pubkey.read().splitlines()[3])
            pubkey.close()

            pubkey = open("./.keypair/id_rsa.pub", "r")
            pubkeyraw = int(pubkey.read().splitlines()[4])
            pubkey.close()

            prikey = open("./.keypair/id_rsa", "r")
            prikeyraw = int(prikey.read().splitlines()[5])
            prikey.close()
        else:
            kp = 0
            print("\n[INFO] - The key pair is not avalaible or key pair is corrupted")
else:
    raise ValueError("\n[ERROR] - Invalid input please try again :< ")

# Encryption, Decryption

ansed = input("Do you want encrypt or decrypt (E or D) : ")

if ansed == "E" or ansed == "e":
    enc()
elif ansed == "D" or ansed == "d":
    dec()
else:
    raise ValueError("\n[Error] - Invalid input please try again :< ")