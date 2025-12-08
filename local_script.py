import sys, hashlib, base64, pathlib, json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Checking the arguments exit is set to 1 (program end)
exit_control = 1
if(len(sys.argv) == 1):
    print("Argument error. try to run 'local_script.py -h' for help.")
else:
    if(sys.argv[1] == "-gen" and len(sys.argv) == 2):
        # Program continue
        exit_control = 0
    elif(sys.argv[1] == "-sign" and len(sys.argv) == 4):
        exit_control = 0
    elif(sys.argv[1] == "-h" and len(sys.argv) == 2):
        exit_control = 0
    else:
        print("Argument error. try to run 'local_script.py -h' for help.")

if(exit_control):
    exit()

# Selected '-gen' param, generation of the keys
if(sys.argv[1] == "-gen"):

    # Private key generation
    def generate_private_key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Private key serializzation
    def serialize_private_key(private_key):
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,                
            format=serialization.PrivateFormat.PKCS8,           
            encryption_algorithm=serialization.NoEncryption()  
        )
        return pem_bytes.decode("utf-8")  

    # Public key generation and serializzation
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    # Generate keys and serialize them
    private_key = generate_private_key()
    private_pem = serialize_private_key(private_key)
    public_pem = serialize_public_key(private_key.public_key())

    # creation of the file .pem containing the keys pairs
    with open("private_key.pem", "w") as f:
        f.write(private_pem)

    with open("public_key.pem", "w") as f:
        f.write(public_pem)

    print("File generation completed. File 'private_key.pem' and 'public_key.pem' are saved on local disk.")

# Selected '-sign' param, the file will be signed with the private key
elif(sys.argv[1] == "-sign"):
    # Get the file path
    file_loaded = sys.argv[2]
    # Get the private key file path
    private_key_file = sys.argv[3]

    # Public key generation and serializzation
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    # Function to calculate hash of the file
    def sha256_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    # Read the content of the file with the "rb" option
    with open(file_loaded, "rb") as f:
        data = f.read()

    # calculate the hash of the file
    hash_file = sha256_bytes(data)

    # function to get the private key from the filepath
    def load_private_key(private_key_path: str):
        pem_data = pathlib.Path(private_key_path).read_bytes()
        private_key = serialization.load_pem_private_key(pem_data, password=None)
        return private_key

    # Function to sign the hash of the file
    def sign_hash(private_key, file_hash: str) -> str:
        signature = private_key.sign(
            file_hash.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    # Calculate the sign
    private_key = load_private_key(private_key_file)
    sign = sign_hash(private_key, hash_file)

    public_key = serialize_public_key(private_key.public_key())

    # Crea JSON con tutti i dati 
    result = {
        "file_name": file_loaded,
        "file_hash": hash_file,
        "signature": sign,
        "public_key": public_key
    }

    json_path = "signature.json"
    with open(json_path, "w") as f:
        json.dump(result, f, indent=4)

    print(f"File firmato correttamente! Output salvato in '{json_path}'")

    # Function to verify the validity of a sign
    def verify_signature(public_key_pem: str, signature_b64: str, file_hash: str) -> bool:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())

        try:
            public_key.verify(
                base64.b64decode(signature_b64),
                file_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    print(verify_signature(public_key, sign, hash_file))
