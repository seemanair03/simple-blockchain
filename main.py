import time

from Block import Block
from Blockchain import Blockchain
from Account import Account

hash_target = ('000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')

alice_account = Account('alice')
bob_account = Account('bob')
carol_account = Account('carol')
dave_account = Account('dave')

block_chain = Blockchain(hash_target)
time.sleep(1)

block_chain.add_account(alice_account)
block_chain.add_account(bob_account)
block_chain.add_account(carol_account)
block_chain.add_account(dave_account)

block_chain.add_transaction(alice_account.create_transaction('bob', 20))
block_chain.add_transaction(bob_account.create_transaction('carol', 30))
block_chain.add_transaction(carol_account.create_transaction('alice', 50))
block_chain.create_new_block()
time.sleep(1)

block_chain.add_transaction(alice_account.create_transaction('dave', 20))
block_chain.add_transaction(dave_account.create_transaction('carol', 35))
block_chain.add_transaction(bob_account.create_transaction('alice', 100))
# This should fail after validation check
block_chain.create_new_block()


print(block_chain)
print(block_chain.get_account_balances())

validation_result = block_chain.validate_blockchain()
if (validation_result):
    print('Validation successful')
else:
    print('Validation failed')

