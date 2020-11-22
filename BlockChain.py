# import string
import binascii
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import datetime
import collections


class User:
    def __init__(self):
        random = Crypto.Random.new().read
        self._private_key = RSA.generate(1024, random)
        self.public_key = self._private_key.publickey()
        self._signer = pkcs1_15.new(self._private_key)

    @property
    def identity(self):
        return binascii.hexlify(self.public_key.exportKey(format='DER')).decode('ascii')


class Transaction:
    transactions = []

    def __init__(self, sender, recipient, value):
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.time = datetime.datetime.now()
        self.signature = ""

    def to_dict(self):
        if self.sender == "Genesis":
            identity = "Genesis"
        else:
            identity = self.sender.identity
        return collections.OrderedDict({
            'sender': identity,
            'recipient': self.recipient,
            'value': self.value,
            'time': self.time
        })

    def sign_transaction(self):
        signer = pkcs1_15.new(self.sender._private_key)
        _hash = SHA256.new(str(self.to_dict()).encode('utf8'))
        self.signature = signer.sign(_hash)
        signature_str = binascii.hexlify(self.signature).decode('ascii')
        Transaction.transactions.append(self)
        return signature_str

    def display_transaction(self):
        t_dict = self.to_dict()
        print('Sender:', t_dict["sender"])
        print('Recipient:', t_dict["recipient"])
        print('Time:', t_dict["time"])
        print('Value:', t_dict["value"])
        print('Signature:', binascii.hexlify(self.signature).decode('ascii'))

    @staticmethod
    def display_allTransactions():
        print("All Transactions: \n")
        for idx, t in enumerate(Transaction.transactions):
            print("Transaction", idx + 1)
            t.display_transaction()
            print("\n")


class Block:

    def __init__(self, transaction, previous_block_hash="", difficulty=4):
        self.transaction = transaction
        self.previous_block_hash = previous_block_hash
        self.difficulty = difficulty
        self.nonce = 0
        self.hash_digest = ""
        self.printLog = True

    def proof_of_work(self):
        # Hash the transaction
        transaction_hash = str(hash(str(self.transaction.to_dict())))
        # Get SHA256 Hash of transaction with nonce
        self.hash_digest = SHA256.new((transaction_hash + str(self.nonce)).encode('ascii')).hexdigest()
        # Find hash_digest according to difficulty
        while not self.hash_digest.startswith('0' * self.difficulty):
            self.nonce += 1
            self.hash_digest = SHA256.new((transaction_hash + str(self.nonce)).encode('ascii')).hexdigest()
            if self.printLog:
                print("\n" + str(self.nonce) + "\n" + self.hash_digest)
            # Return if hash digest not found after 500,000 iterations
            if self.nonce >= 500000:
                print("\n\nCould NOT Find Hash Digest Even After " + str(self.nonce) + " Iterations!\n\n")
                return False
        # Hash has been found
        print("\nFound Hash Digest After " + str(self.nonce) + " Iterations!\n\n")
        return True


class BlockChain:

    def __init__(self):
        self.valid_transactions = []
        self.currentBlockHash = ""
        self.printLog = True

    # Validate all available transactions
    def validate_transactions(self):
        for transaction in Transaction.transactions:
            if self.verify_transaction(transaction):
                block = Block(transaction, self.currentBlockHash)
                block.printLog = self.printLog
                if block.proof_of_work():
                    self.valid_transactions.append(block)
                    self.currentBlockHash = block.hash_digest

    # Verify the digital signature of the transaction before validating using PoW
    def verify_transaction(self, transaction):
        try:
            Crypto.Signature.pkcs1_15.new(transaction.sender.public_key).verify(
                SHA256.new(str(transaction.to_dict()).encode('utf8')), transaction.signature)
            print("The signature is valid.")
            return True
        except (ValueError, TypeError):
            print("The signature is not valid.")
            return False

    def display_valid_transactions(self):
        print("All Valid Transactions (" + str(len(self.valid_transactions)) + "): \n")
        for idx, block in enumerate(self.valid_transactions):
            print("Transaction", idx + 1)
            block.transaction.display_transaction()
            print("Hash: " + block.hash_digest)
            print("Nonce: " + str(block.nonce))
            print("Difficulty: " + str(block.difficulty))
            print("\n")


# Create Users
user1 = User()
user2 = User()
user3 = User()
user4 = User()

# Create Transactions between Users
t1 = Transaction(user1, user2.identity, 100)
t1.sign_transaction()

t2 = Transaction(user2, user3.identity, 500)
t2.sign_transaction()

t3 = Transaction(user3, user4.identity, 20)
t3.sign_transaction()

t4 = Transaction(user1, user4.identity, 50)
t4.sign_transaction()

# Transaction.display_allTransactions()

# Create blockchain
blockchain = BlockChain()
blockchain.printLog = False  # Do not display iterations
blockchain.validate_transactions()

# Display Valid Transactions
blockchain.display_valid_transactions()
