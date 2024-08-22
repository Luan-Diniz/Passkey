import secrets, base64
import psycopg2 as pg
from flask import Flask, request, jsonify
from os import getcwd, getenv
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

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

challenges = {}  # username : challenge
app = Flask(__name__)
conn = pg.connect(database=DB_NAME, user=DB_USER, password=DB_PASSWORD,
                  host=DB_HOST, port='5432')

def create_challenge(username: str) -> str:
    '''
        Creates a random challenge (bytes) to be signed.
    '''
    challenge = secrets.token_hex(CHALLENGE_SIZE)
    challenges[username] = challenge

    return challenge


@app.route('/', methods = ['GET'])
def welcome():
    '''
        Just for testing connection.
    '''
    return "Welcome to the PassKey Authentication!"

@app.route('/signin', methods = ['POST'])
def sign_in():
    '''
        Starts the sign in process.
        Should receive a username, and return a random challenge (to be signed).
        The answer of the challenge should be send to /challengeanswer
    '''
    data = request.json

    return {'username': data['username'],
            'challenge': create_challenge(data['username'])}

@app.route('/challengeanswer', methods = ['POST'])
def verify_challenge():
    '''
        Verify if the signature received is authentic.
    '''
    data = request.json
    signature = base64.b64decode(data['signature'])

    # Fetchs client public key.
    with conn.cursor() as curs:
        curs.execute("SELECT public_key FROM users WHERE username = %s;",
                     (data['username'],))
        conn.commit()
        query_result = curs.fetchone()      # fetchone because 'username' is UNIQUE
        if query_result == None:    
            return {"Failed": "This username does not exist."}, 409
    
    client_public_key = query_result[0].encode('utf-8')
    client_public_key = RSA.import_key(client_public_key).public_key()

    # Verifies signature.
    data_hash = SHA256.new()
    data_hash.update(challenges[data['username']].encode('utf-8'))
    signer = pkcs1_15.new(client_public_key)

    try:
        signer.verify(signature=signature, msg_hash=data_hash)
        '''
            The propose of this application is just realizing the log in.
            How to handle it from here was not coded.
            Probably would use an authtoken and jwt!
        '''
        return {'Sucess': f"User {data['username']} has logged in!"}
    except ValueError:
        return {'Failed': 'Signature is NOT authentic.'}, 401
    

@app.route('/signup', methods = ['POST'])
def sign_up():
    '''
    Register the user.
    Should receive a username and a public key.
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
            curs.execute("INSERT INTO users (username, public_key) VALUES (%s, %s);",
                        (data['username'], data['public_key']))
        conn.commit()
        return request.json
    except pg.Error as e:
        conn.rollback()
        print(f"Database error: {e}")
        return jsonify({"error": "Database error occurred"}), 500
    

app.run(host=HOST)
conn.close()