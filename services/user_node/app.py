import requests
from anoncreds import *

# Configurations
PRIVATE_KEY_FILE_NAME = "myprivatekey.pem"
SERVER_ADDRESS = "http://localhost:5000"  # IP address + PORT
SERVER_ENDPOINT_SIGNIN = "/signin"
SERVER_ENDPOINT_SIGNUP = "/signup" 
SERVER_ENDPOINT_RECEIVE_CREDENTIAL_REQUEST = "/receive_credential_request"
SERVER_ENDPOINT_RECEIVE_CREDENTIAL_PRESENTATION = "/receive_credential_presentation"


# Credential

entropy = "entropy"
link_secret = create_link_secret()  
link_secret_id = "default"


def exit_program():
    print('Exiting the program...')
    exit()

def asks_username(text: str) -> str:
    username = ""
    while username == "":
        username = input(text)
    return username


while True:

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

        data = response.json()

        pres_req = PresentationRequest.load(data['pres_req'])
        rev_state = CredentialRevocationState.load(data['rev_state'])
        schema = Schema.load(data['schema'])
        cred_def_pub = CredentialDefinition.load(data['cred_def_pub'])
        schema_id = data['schema_id']
        cred_def_id = data['cred_def_id']

        time_after_creating_cred = data['time_after_creating_cred']
        schemas = {schema_id: schema}               
        cred_defs = {cred_def_id: cred_def_pub}


        try:
            with open("credential.json", "r") as f:
                recv_cred = W3cCredential.load(f.read())
        except FileNotFoundError:
            print('Your credential was not found!')
            exit_program()

        try:
            with open("link_secret", "r") as f:
                link_secret = f.read()
        except FileNotFoundError:
            print('Your link secret was not found!')
            exit_program()
        

        # Create Presentation using W3C credential
        present = PresentCredentials()

        present.add_attributes(
            recv_cred,
            "attr1_referent",
            reveal=True,
            timestamp=time_after_creating_cred,
            rev_state=rev_state,
        )

        present.add_attributes(
            recv_cred,
            "attr2_referent",
            reveal=True,
            timestamp=time_after_creating_cred,
            rev_state=rev_state,
        )

        presentation = W3cPresentation.create(
            pres_req,
            present,
            link_secret,
            schemas,
            cred_defs,
        )


        #Send presentation to server.
        response = requests.post(
            SERVER_ADDRESS + SERVER_ENDPOINT_RECEIVE_CREDENTIAL_PRESENTATION,  
            json = {'presentation': presentation.to_json(),
                    'username' : username }
        )
        if response.status_code != 200:
            print(f"Request failed with status code: {response.status_code}\n")
            print(response.json())
            exit_program()

        data = response.json()
        print(data)

        

    elif user_input == '2':
        # Asks for username
        username = asks_username("Choose your username:\n")

        # Creates the request
        request_body = {
            "username": username
        }   

        response = requests.post(
            SERVER_ADDRESS + SERVER_ENDPOINT_SIGNUP,
            json= request_body
        )
        if response.status_code != 200:
            print(f"Request failed with status code: {response.status_code}\n")
            print(response.json())
            exit_program()

        print('Response received')   
        # Creates Credential Request.
        cred_offer = CredentialOffer.load(response.json()['cred_offer'])
        cred_def_pub = CredentialDefinition.load(response.json()['cred_def_pub'])
        token = response.json()['token']

        cred_request, cred_request_metadata = CredentialRequest.create(                    
            entropy, None, cred_def_pub, link_secret, link_secret_id, cred_offer
        )

        request_body = {
            "cred_request" : cred_request.to_json(),
            "cred_offer" : cred_offer.to_json(),
            "token" : token,
            "username" : username
        }

        response = requests.post(
            SERVER_ADDRESS + SERVER_ENDPOINT_RECEIVE_CREDENTIAL_REQUEST,
            json= request_body
        )

        issue_cred = W3cCredential.load(response.json()["issue_cred"])
        rev_reg_def_pub = RevocationRegistryDefinition.load(response.json()["rev_reg_def_pub"])

        recv_cred = issue_cred.process(                                                 
            cred_request_metadata, link_secret, cred_def_pub, rev_reg_def_pub
        )

        with open("link_secret", "w") as f:
            f.write(link_secret)


        with open("credential.json", "w") as f:
            f.write(recv_cred.to_json())

        
    else:
        exit_program()