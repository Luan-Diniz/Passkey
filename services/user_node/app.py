import requests, base64
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# Configurations
PRIVATE_KEY_FILE_NAME = "myprivatekey.pem"
SERVER_ADDRESS = "http://localhost:5000"  # IP address + PORT
SERVER_ENDPOINT_SIGNIN = "/signin"
SERVER_ENDPOINT_SIGNUP = "/signup" 
SERVER_ENDPOINT_CHALLENGE_ANSWER = "/challengeanswer"

def exit_program():
    print('Exiting the program...')
    exit()

def asks_username(text: str) -> str:
    username = ""
    while username == "":
        username = input(text)
    return username

def asks_private_key_file_password() -> bytes:
    private_key_password = input("Write the password for your private key file: \
                                 \n(Or leave it blank if you don't want to.)\n").encode('utf-8')    
    return (private_key_password or None)  # Short-circuit evaluation. b'' returns False.


user_input = input("What do you want to do? \n\t1-Sign In\n\t2-Sign Up\n\t3-Exit\n")
if user_input == '1':
    username = asks_username("What's your username?\n")

    # Create post request
    response = requests.post(
        SERVER_ADDRESS + SERVER_ENDPOINT_SIGNIN,
        json= {'username': username}
    )
    if response.status_code != 200:
        print(f"Request failed with status code: {response.status_code}\n")
        print(response.json())
        exit_program()

    # Store the challenge
    challenge = response.json()['challenge']

    # Asks for a password for the private key file.
    private_key_password = asks_private_key_file_password()

    try:
        with open("myprivatekey.pem", "rb") as f:
            data = f.read()
            user_key = RSA.import_key(data, private_key_password)
    except ValueError:
        print('Wrong password!')
        exit_program()
    except FileNotFoundError:
        print('Your private key was not found!')
        exit_program()

    # Signs the challenge.
    data_hash = SHA256.new()
    data_hash.update(challenge.encode('utf-8'))

    signer = pkcs1_15.new(user_key)
    signature = signer.sign(data_hash)

    # Signature to base64 and POST request
    encoded_signature = base64.b64encode(signature).decode('utf-8')
    response = requests.post(
        SERVER_ADDRESS + SERVER_ENDPOINT_CHALLENGE_ANSWER,
        json= {'username': username,
               'signature': encoded_signature}
    )
    if response.status_code != 200:
        print(f"Request failed with status code: {response.status_code}\n")
        print(response.json())
        exit_program()
    
    print(response.json())  # TODO: output status to the user
    

elif user_input == '2':
    # Creates keypair
    key_pair = RSA.generate(2048)

    # Asks for username
    username = asks_username("Choose your username:\n")

    # Asks for a password for the private key file.
    private_key_password = asks_private_key_file_password()

    # Stores private key in a .pem file.
    with open(PRIVATE_KEY_FILE_NAME , "wb") as f:
        data = key_pair.export_key(passphrase=private_key_password,
                                    pkcs=8,
                                    protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                    prot_params={'iteration_count':131072})
        f.write(data)

    public_key = key_pair.public_key().export_key()
    public_key = public_key.decode()

    # Creates the request
    request_body = {
        "username": username,
        "public_key": public_key
    }   

    response = requests.post(
        SERVER_ADDRESS + SERVER_ENDPOINT_SIGNUP,
        json= request_body
    )
    if response.status_code != 200:
        print(f"Request failed with status code: {response.status_code}\n")
        print(response.json())
        exit_program()

    print('Response received')   #
    print(response.json())   # for testing

else:
    exit_program()