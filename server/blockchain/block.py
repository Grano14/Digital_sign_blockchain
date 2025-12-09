import time

# implementation of the Block class
class Block:
    def __init__(self, index, data, previous_hash, nonce=0, timestamp=None):
        self.index = index
        self.timestamp = timestamp or time.time()
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        # inizialized to None, after it will be change
        self.hash = None 

    # return the block as a dictionary
    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }
