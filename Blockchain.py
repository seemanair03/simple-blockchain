import json
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

from Block import Block


class Blockchain:
    # Basic blockchain init
    # Includes the chain as a list of blocks in order, pending transactions, and known accounts
    # Includes the current value of the hash target. It can be changed at any point to vary the difficulty
    # Also initiates a genesis block
    def __init__(self, hash_target):
        self._chain = []
        self._pending_transactions = []
        self._chain.append(self.__create_genesis_block())
        self._hash_target = hash_target
        self._accounts = {}

    def __str__(self):
        return f"Chain:\n{self._chain}\n\nPending Transactions: {self._pending_transactions}\n"

    @property
    def hash_target(self):
        return self._hash_target

    @hash_target.setter
    def hash_target(self, hash_target):
        self._hash_target = hash_target

    # Creating the genesis block, taking arbitrary previous block hash since there is no previous block
    # Using the famous bitcoin genesis block string here :)  
    def __create_genesis_block(self):
        genesis_block = Block(0, [], 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks', 
            None, 'Genesis block using same string as bitcoin!')
        return genesis_block

    def __validate_transaction(self, transaction):
        # Serialize transaction data with keys ordered, and then convert to bytes format
        hash_string = json.dumps(transaction['message'], sort_keys=True)
        encoded_hash_string = hash_string.encode('utf-8')
        
        # Take sha256 hash of the serialized message, and then convert to bytes format
        message_hash = hashlib.sha256(encoded_hash_string).hexdigest()
        encoded_message_hash = message_hash.encode('utf-8')

        # Signature - Encode to bytes and then Base64 Decode to get the original signature format back 
        signature = base64.b64decode(transaction['signature'].encode('utf-8'))

        try:
            # Load the public_key object and verify the signature against the calculated hash
            sender_public_pem = self._accounts.get(transaction['message']['sender']).public_key
            sender_public_key = serialization.load_pem_public_key(sender_public_pem)
            sender_public_key.verify(
                                        signature,
                                        encoded_message_hash,
                                        padding.PSS(
                                            mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH
                                        ),
                                        hashes.SHA256()
                                    )
        except InvalidSignature:
            return False
        return True

    def __process_transactions(self, transactions):
        # Appropriately transfer value from the sender to the receiver
        # For all transactions, first check that the sender has enough balance. 
        # Return False otherwise
        valid_transactions = []
        return_value = True
        print("\nAccounts state:")
        current_balance = self.get_account_balances()
        for record in current_balance:
            print(f"Name= {record['id']}: Value= {record['balance']}")
        print("\n------------Processing transactions for new block...------------")
        for t in transactions:
            sender_balance = self._accounts.get(t['message']['sender']).balance
            if (sender_balance >= t['message']['value']):
                self._accounts.get(t['message']['sender']).decrease_balance(t['message']['value'])
                self._accounts.get(t['message']['receiver']).increase_balance(t['message']['value'])
                valid_transactions.append(t)
                print(f"PROCESSED: Transfer {t['message']['value']} from {t['message']['sender']} to {t['message']['receiver']}")
            else:
                print(f"PROCESSING FAILURE: {t['message']['sender']} does not have sufficient balance to transfer {t['message']['value']} to {t['message']['receiver']}'s account!")
                return_value = False
            self._pending_transactions = valid_transactions
        #print("\n----------------------------------------------------------------")
        print("------------Processed transactions for new block!---------------\n\n")

        return return_value

    # Creates a new block and appends to the chain
    # Also clears the pending transactions as they are part of the new block now
    def create_new_block(self):
        new_block = Block(len(self._chain), self._pending_transactions, self._chain[-1].block_hash, self._hash_target)
        if self.__process_transactions(self._pending_transactions):
            self._chain.append(new_block)
            self._pending_transactions = []
            return new_block
        else:
            new_block = Block(len(self._chain), self._pending_transactions, self._chain[-1].block_hash, self._hash_target)
            self._chain.append(new_block)
            self._pending_transactions = []
            return new_block


    # Simple transaction with just one sender, one receiver, and one value
    # Created by the account and sent to the blockchain instance
    def add_transaction(self, transaction):
        if self.__validate_transaction(transaction):
            self._pending_transactions.append(transaction)
            return True
        else:
            print(f'ERROR: Transaction: {transaction} failed signature validation')
            return False


    def __validate_chain_hash_integrity(self):
        # Run through the whole blockchain and ensure that previous hash is actually the hash of the previous block
        # Return False otherwise
        for index in range(1, len(self._chain)):
            if (self._chain[index].previous_block_hash != self._chain[index - 1].hash_block()):
                print(f'\n\nPrevious block hash mismatch in block index: {index}')
                return False
        print("\n\nValidated chain hash integrity!")
        return True

    def __validate_block_hash_target(self):
        # Run through the whole blockchain and ensure that block hash meets hash target criteria, and is the actual hash of the block
        # Return False otherwise

        for index in range(1, len(self._chain)):

            # Check block hash meets hash target criteria
            if (int(self._chain[index].block_hash, 16) >= int(self._chain[index].hash_target, 16)):
                print(f'Hash target not achieved in block index: {index}')
                return False

            # Check that hash is the actual hash of the block
            hash_blockstring = '-'.join([
                str(self._chain[index]._index),
                str(self._chain[index]._timestamp),
                str(self._chain[index]._previous_block_hash),
                str(self._chain[index]._metadata),
                str(self._chain[index]._hash_target),
                str(self._chain[index]._nonce),
                json.dumps(self._chain[index]._transactions, sort_keys=True)
            ])
            encoded_hash_string = hash_blockstring.encode('utf-8')
            block_hash_new = hashlib.sha256(encoded_hash_string).hexdigest()

            if block_hash_new != self._chain[index].block_hash:
                print(f'Hash is not the actual hash of the block index: {index}')
                return False

            print(f'Validated block hash for block {self._chain[index]._index}!')

        return True

    def __validate_complete_account_balances(self):
        # Run through the whole blockchain and ensure that balances never become negative from any transaction
        # Return False otherwise

        # Get initial or starting total balance
        ini_bal = [{'id': account.id, 'balance': account.initial_balance} for account in self._accounts.values()]
        starting_bal = 0
        for j in ini_bal:
            starting_bal = starting_bal + j["balance"]

        # Create temporary list to hold the transaction states
        temp_list = []
        for account in self._accounts.values():
            temp_list.append({'t_id': account.id, 't_balance': account.initial_balance})

        # Loop through each block starting from block 1
        for index in range(1, len(self._chain)):
            t_trans = []
            t_trans = self._chain[index]._transactions

            # Loop through each trasaction in the given block
            for t in t_trans:

                # Update the state in temporary list for each transaction execution
                for k in temp_list:
                    if t["message"]["sender"]==k['t_id']:
                        k['t_balance'] = k['t_balance'] - t["message"]["value"]

                        # Fail the validation if any account balance becomes negative
                        if k['t_balance'] < 0:
                             return False

                    elif t["message"]["receiver"] == k['t_id']:
                        k['t_balance'] = k['t_balance'] + t["message"]["value"]

                # Check total balance in all accounts after given transaction execution
                total_bal = 0
                for c in temp_list:
                    total_bal = total_bal + c["t_balance"]

                # Fail the validation if the total balance after transaction is not same as initial starting balance
                # This is to check consistency of the blockchain.
                if total_bal != starting_bal:
                    return False

        print("Validated complete account balances!")
        return True

    # Blockchain validation function
    # Runs through the whole blockchain and applies appropriate validations
    def validate_blockchain(self):
        return_value = None
        # Call __validate_chain_hash_integrity and implement that method. Return False if check fails
        val_chain_hash_integrity = self.__validate_chain_hash_integrity()

        # Call __validate_block_hash_target and implement that method. Return False if check fails
        val_block_hash_target = self.__validate_block_hash_target()

        # Call __validate_complete_account_balances and implement that method. Return False if check fails
        val_complete_account_balance = self.__validate_complete_account_balances()

        if val_chain_hash_integrity and val_block_hash_target and val_complete_account_balance:
            return True
        else:
            return False

    def add_account(self, account):
        self._accounts[account.id] = account

    def get_account_balances(self):
        return [{'id': account.id, 'balance': account.balance} for account in self._accounts.values()]



