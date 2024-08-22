from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


# htts://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
key_pair = RSA.generate(2048)
public_key = key_pair.public_key()
#print(key_pair)
#print(public_key)

# Passphrases usually are env variables and we get it using os.getenv('PRIVATE_KEY_PASSPHRASE')
# https://pycryptodome.readthedocs.io/en/latest/src/signature/signature.html 
# Signing data (client side)
data_to_be_signed = "criandoumaengenhoca"
signer = pkcs1_15.new(key_pair)
data_hash = SHA256.new()
data_hash.update(data_to_be_signed.encode('utf-8'))
#print(data_hash.hexdigest())

signature = signer.sign(data_hash)
#print(signature)

# Verifying the signature (server side)
signer = pkcs1_15.new(public_key)
# We should have the data_hash as well!
try:
    signer.verify(signature=signature, msg_hash=data_hash)
except ValueError:
    print('Signature is NOT authentic.')


# Encoding the key in PEM, and see if it doesnt lose information in casting between str and bytes.
pem_public_key = public_key.export_key()
#print(type(pem_public_key))
#print(len(pem_public_key))
#pem_public_key = pem_public_key.decode()
#pem_public_key = pem_public_key.encode('utf-8')
#print(type(pem_public_key))
#print(len(pem_public_key))

imported_public_key = RSA.import_key(pem_public_key)
imported_public_key = imported_public_key