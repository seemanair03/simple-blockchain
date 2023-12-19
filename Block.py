import time
import hashlib
import json

class Block:
    # Basic block init
    # Index: The position of the block in the chain starting with 0 for the genesis block
    # Timestamp: Time when the block was created
    # Transactions: Transactions included in the block
    # Previous block hash: Block hash of the previous block
    # Hash target: Block hash should be below this target
    # Nonce: Variable that miners vary to hit the hash target
    # Metadata: Any generic textual information added in the block (Optional)
    # Block hash: Hash of the current block including all the aforementioned data
    def __init__(self, index, transactions, previous_block_hash, hash_target, metadata=''):
        self._index = index
        self._timestamp = time.time()
        self._transactions = transactions
        self._previous_block_hash = previous_block_hash
        self._metadata = metadata
        self._hash_target = hash_target
        self._nonce = 0
        self._block_hash = None
        self.mine_block()

    def __str__(self):
        return f'\nBlock index: {self._index}\nTimestamp: {self._timestamp}\nTransactions: {self._transactions}\nPrevious Block Hash: {self._previous_block_hash}\nMetadata: {self._metadata}\nHash Target: {self._hash_target}\nNonce: {self._nonce}\nBlock Hash: {self._block_hash}\n'

    #__repr__ is called on the individual elements (instead of __str__) 
    # if you try to print a list of the items or objects
    def __repr__(self):
        return self.__str__()

    @property
    def block_hash(self):
        return self._block_hash

    @property
    def previous_block_hash(self):
        return self._previous_block_hash

    @property
    def hash_target(self):
        return self._hash_target

    # Serializing and utf-8 encoding relevant data, and then hashing and creating a hex representation
    def hash_block(self):
        hash_string = '-'.join([
                                str(self._index),
                                str(self._timestamp),
                                str(self._previous_block_hash),
                                str(self._metadata),
                                str(self._hash_target),
                                str(self._nonce),
                                json.dumps(self._transactions, sort_keys=True)
                                ])
        encoded_hash_string = hash_string.encode('utf-8')
        block_hash = hashlib.sha256(encoded_hash_string).hexdigest()
        return block_hash

    # Increasing nonce until block hash is below the hash target
    # Ignoring for genesis block (index 0) since that block is hard-coded
    def mine_block(self):
        if (self._index != 0):
            while (int(self.hash_block(), 16) > int(self._hash_target, 16)):
                self._nonce += 1
        self._block_hash = self.hash_block()
        return True
