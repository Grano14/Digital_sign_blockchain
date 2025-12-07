from fastapi import FastAPI, UploadFile, File
import hashlib

from blockchain.blockchain import Blockchain

app = FastAPI()
blockchain = Blockchain()

def hash_file(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

@app.get("/")
def root():
    return {"message": "Blockchain Notary Service"}

@app.post("/notarize")
async def notarize(file: UploadFile):
    file_bytes = await file.read()
    file_hash = hash_file(file_bytes)
    block = blockchain.add_block(file_hash)
    return {"message": "File notarized", "hash": file_hash, "block": block.to_dict()}

@app.get("/chain")
def get_chain():
    return [b.to_dict() for b in blockchain.chain]

@app.get("/verify/{file_hash}")
def verify(file_hash: str):
    for block in blockchain.chain:
        if block.data == file_hash:
            return {"valid": True, "block": block.to_dict()}
    return {"valid": False}
