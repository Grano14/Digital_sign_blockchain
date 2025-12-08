from blockchain.block import Block
from blockchain.pow import proof_of_work

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis = Block(0, "GENESIS", "0")
        proof_of_work(genesis)
        self.chain.append(genesis)

    def add_block(self, data):
        prev_block = self.chain[-1]
        new_block = Block(
            index = prev_block.index + 1,
            data = data,
            previous_hash = prev_block.hash
        )
        proof_of_work(new_block)
        self.chain.append(new_block)
        return new_block
    
    def is_valid(self):
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            if curr.previous_hash != prev.hash:
                return False

            calculated_hash = proof_of_work(curr)
            if curr.hash != calculated_hash:
                return False

        return True
