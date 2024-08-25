import secrets
import psycopg2 as pg
from anoncreds import *
from flask import Flask, request, jsonify
from os import getcwd, getenv

# Configuration from environment variables
DB_NAME = getenv("DB_NAME", "mydb")
DB_USER = getenv("DB_USER", "postgres_user")
DB_PASSWORD = getenv("DB_PASSWORD", "password")
DB_HOST = getenv("DB_HOST", "passkey-db")  # passkey-db is the name of the container Postgres is running.
DB_PORT = getenv("DB_PORT", "5432")

HOST = '0.0.0.0'
CHALLENGE_SIZE = 32 # 32 bytes or 256 bits
# Check if it is running in Docker.
if getcwd() != '/server_api':
    HOST = '127.0.0.1'

# Credential
issuer_id = "mock:uri"
schema_id = "mock:uri"
cred_def_id = "mock:uri"
rev_reg_id = "mock:uri:revregid"
rev_idx = 1
time_after_creating_cred = None
issued_rev_status_list = None

schema = Schema.create(
    "schema name", "schema version", issuer_id, ["name"]
)

cred_def_pub, cred_def_priv, cred_def_correctness = CredentialDefinition.create(
    schema_id, schema, issuer_id, "tag", "CL", support_revocation=True
)

(rev_reg_def_pub, rev_reg_def_private) = RevocationRegistryDefinition.create(
    cred_def_id, cred_def_pub, issuer_id, "some_tag", "CL_ACCUM", 10
)

time_create_rev_status_list = 12
revocation_status_list = RevocationStatusList.create(
    cred_def_pub,
    rev_reg_id,
    rev_reg_def_pub,
    rev_reg_def_private,
    issuer_id,
    True,
    time_create_rev_status_list,
)


presentation_requests = {}  # username : pres_req
tokens = {}  # username : challenge
app = Flask(__name__)
conn = pg.connect(database=DB_NAME, user=DB_USER, password=DB_PASSWORD,
                  host=DB_HOST, port='5432')

def create_token(username: str) -> str:
    '''
        Binds a random token (bytes) to a username while the Credential
    is been created.
    '''
    token = secrets.token_hex(CHALLENGE_SIZE)
    tokens[username] = token

    return token


@app.route('/signup', methods = ['POST'])
def sign_up():
    '''
    Register the user.
    Should receive a username.
    Returns a CredentialOffer, CredentialDefinition and a token.
    '''
    data = request.json 

    # Verify if that username isnt in the database
    with conn.cursor() as curs:
        curs.execute("SELECT COUNT(*) FROM users WHERE username = %s;",
                     (data['username'], ))
        conn.commit()
        if curs.fetchone()[0] != 0:
            return {"Failed": "This username is already taken."}, 409
    
    # Inserts new user info in to the database
    try:
        with conn.cursor() as curs:
            curs.execute("INSERT INTO users (username) VALUES (%s);",
                        (data['username'],))
        conn.commit()
        
    except pg.Error as e:
        conn.rollback()
        print(f"Database error: {e}")
        return jsonify({"error": "Database error occurred"}), 500
    

    # Start creating the credential.
    cred_offer = CredentialOffer.create(schema_id, cred_def_id, cred_def_correctness)

    return {"cred_offer" : cred_offer.to_json(),
            "cred_def_pub" : cred_def_pub.to_json(),
            "token" : create_token(data['username'])
            }

@app.route('/signin', methods = ['POST'])
def sign_in():
    '''
        Starts the sign in process.
        Should receive a username.
        Returns a PresentationRequest and other information, so
    the Holder can create a Presentation and send it to /receive_credential_presentation.
    '''
    global issued_rev_status_list
    global time_after_creating_cred

    data = request.json

    time_after_creating_cred = time_create_rev_status_list + 1
    issued_rev_status_list = revocation_status_list.update(
        cred_def_pub,
        rev_reg_def_pub,
        rev_reg_def_private,
        [rev_idx],
        None,
        time_after_creating_cred,
    )

    nonce = generate_nonce()
    pres_req = PresentationRequest.load(
        {
            "nonce": nonce,
            "name": "pres_req_1",
            "version": "0.1",
            "requested_attributes": {
                "attr1_referent": {"name": "name", "issuer_id": issuer_id},
                "attr2_referent": {"names": ["name"]},
            },
            "non_revoked": {"from": 10, "to": 200},
        }
    )


    presentation_requests[data['username']] = pres_req.to_json()

    rev_state = CredentialRevocationState.create(
        rev_reg_def_pub,
        revocation_status_list,
        rev_idx,
        rev_reg_def_pub.tails_location,
    )

    return {'pres_req': pres_req.to_json(),
            'rev_state' : rev_state.to_json(),
            'schema_id' : schema_id,
            'schema' : schema.to_json(), 
            'cred_def_id' : cred_def_id,
            'cred_def_pub' : cred_def_pub.to_json(),
            'time_after_creating_cred' : time_after_creating_cred}

@app.route('/receive_credential_request', methods = ['POST'])
def process_credential_request():
    '''
        After receiving the CredentialOffer, the Holder should
    create a CredentialRequest.
        This endpoint receives the CredentialRequest and returns
    a signed Credential.
    '''
    data = request.json 
    cred_offer = CredentialOffer.load(data["cred_offer"])
    cred_request = CredentialRequest.load(data["cred_request"])
    token = data["token"]
    username = data["username"]
    
    # Validate token and username.
    try:
        if tokens[username] != token:
            return {'Failed': 'NOT authentic token.'}, 401
    except KeyError:
            return {'Failed' : "User didn't create a credential request!" }


    # Creates and signs the credential
    issue_cred = W3cCredential.create(
        cred_def_pub,
        cred_def_priv,
        cred_offer,
        cred_request,
        {"name": username},
        CredentialRevocationConfig(
            rev_reg_def_pub,
            rev_reg_def_private,
            revocation_status_list,
            rev_idx,
        ),
        None,
    )
                  
    # Holder already have cred_def_pub.
    return {                            
            "issue_cred" :   issue_cred.to_json(),
            "rev_reg_def_pub" : rev_reg_def_pub.to_json()            
        }

@app.route("/receive_credential_presentation", methods = ['POST'])
def process_credential_presentation():
    '''
        Verify if the CredentialPresentation is authentic.
    '''
    data = request.json

    presentation = W3cPresentation.load(data['presentation'])
    schemas = {schema_id: schema}               
    cred_defs = {cred_def_id: cred_def_pub}
    rev_reg_defs = {rev_reg_id: rev_reg_def_pub}
    rev_status_lists = [issued_rev_status_list]


    #Verify if username is the same in presentation request.
    cred_subject = presentation.to_dict()[
        "verifiableCredential"][0]["credentialSubject"]["name"]
    
    if (cred_subject != data['username']):
        return {"Failed": "Credential doesn't match username."}, 401

    pres_req = PresentationRequest.load(
        presentation_requests[data['username']])

    verified = presentation.verify(              
        pres_req, schemas, cred_defs, rev_reg_defs, rev_status_lists
    )
    
    if verified:
        return {'Sucess': f"User {data['username']} has logged in!"}
    else:
        return {'Failed': 'Credential is NOT authentic.'}, 401


app.run(host=HOST)
conn.close()