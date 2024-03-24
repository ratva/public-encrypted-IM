
import binascii
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def verifyMessage(message, signature):
    message = message.encode("utf-8")
    key = RSA.import_key(open('mypubkey.pem').read())
    signature = binascii.unhexlify(signature)
    h = SHA256.new(message)

    try:
        pkcs1_15.new(key).verify(h, signature)
        print("The signature is valid.")

    except (ValueError, TypeError):
        print("The signature is not valid.")

verifyMessage('test','a6d25a4a282b4d60a57ce70ff9f253b96d2edabf7286fe3060836488ccc9a30fd823624ecfa268f8e87be1ddf246ab49fe6be0c7ed684cd6ce80471bd75cae71290eb8469e154c706f9f797991fc91e5ad531de3b14d51390759fb9211c01877ac21adf627882e11322fe407153d96b4ec3a19114a48aa6cf17c51ad3427b709f59f6b4cb88649a4deb0ff0812d1bdc5b43ae848bd61c6c3924b2139e2a7d142c50cf44c01feea3d42f54b93e1b60eb14378fce2553f1ff368a941f033d63d5879ff0556baa52a3ca5bcca799b73b3e73721ac75349ffd4f90e85e00fdf69f67cac51e3fca567119077b63bb59843ee5349978e93c30788f9fc4667172f9c6cb171c858c4ab70e66f06d4dcd9d61fc289fee11f08201b09872ff42126e843e5aeac117ee96480b661324d68b01aaf991df7d3b91b1664bba7b7a9fe09bd6299fc670819b94b9e097c02e32bf40ac4858032ebe5080206b3ab20dd33e8bdd5550b59c7bda7556261ef72b9c2ddf60b7a90222d861a9bbab0899025de92b09053441d09e0dead4c961e9051f7cf636f29ced001b3b15859aecb37a393ae732e32c81852016999e634ae209478968504dfd6ab5fbf235356cb4db932b1e5aa003260a6d7e3fdb450c0d0824e3004053979ad5f095d07cac90e57d0d17fbf4f348c248bf5cb5152f06744605db626dde45523d8858494d0fdf31bfd374fd320c3450')