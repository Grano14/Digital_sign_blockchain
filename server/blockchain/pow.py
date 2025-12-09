import hashlib
import json

# difficulty value indicate the number of 0 in the prefix of the calculate hash
difficulty = 2

# wrapper class of sha256 so that it can process directly the block in dict
def sha256(data):
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True).encode()
    elif isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

# pow algorithm
def proof_of_work(block):
    prefix = "0" * difficulty

    # try to calculate an hash that start with "00"
    while True:
        block.hash = sha256({
            "index": block.index,
            "timestamp": block.timestamp,
            "data": block.data,
            "previous_hash": block.previous_hash,
            "nonce": block.nonce
        })

        if block.hash.startswith(prefix):
            return block.hash

        # the actual nonce is increased so that the next hash calculation result will change
        block.nonce += 1

