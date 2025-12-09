from fastapi import FastAPI, UploadFile, File
import hashlib, base64, json
import tempfile
import zipfile

from blockchain.blockchain import Blockchain
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


app = FastAPI()
blockchain = Blockchain()

@app.get("/")
def root():
    return {"message": "Blockchain Digital Sign Service"}

@app.post("/notarize")
async def notarize(data: dict):
    block = blockchain.add_block(data)
    return {"message": "File notarized", "hash": data.get("file_hash"), "signature": data.get("signature"), "block": block.to_dict()}

@app.get("/chain")
def get_chain():
    return [b.to_dict() for b in blockchain.chain]

@app.get("/signature/{hash}")
def get_signature(hash: str):
    for block in blockchain.chain:
        data = block.data

        if(data == "GENESIS"):
            continue

        # If find the file hash return his signature
        if data.get("file_hash") == hash:
            return {"found": True, "signature": data.get("signature"), "public_key": data.get("public_key")}
        else:
            return {"found": False, "reason": "Hash not found"}

@app.get("/verify/{file_hash}")
def verify(file_hash: str):
    for block in blockchain.chain:
        data = block.data

        if(data == "GENESIS"):
            continue

        if data.get("file_hash") == file_hash:

            # 1) ricostruisci la chiave pubblica
            public_key = serialization.load_pem_public_key(
                data.get("public_key").encode()
            )

            signature = base64.b64decode(data["signature"])

            # 2) verifica la firma
            try:
                public_key.verify(
                    signature,
                    file_hash.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception:
                return {"valid": False, "reason": "Invalid signature"}

            # 3) opzionale: verifica integrità blockchain
            if not blockchain.is_valid():
                return {"valid": False, "reason": "Blockchain corrupted"}

            return {
                "valid": True,
                "signed_by_public_key": data["public_key"],
                "block": block.to_dict()
            }

    return {"valid": False, "reason": "Hash not found"}
