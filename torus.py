#!/usr/bin/env python

#executed by running using python3 - python3 torus.py in current directory 
#wallets and transactions can be changed in __main__

#requires Crypto library - can be installed with pycryptodome by running
#			   "pip install pycryptodome==3.4.3"

from datetime import datetime
from Crypto.PublicKey import RSA  
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import base64

'''
The code below is an extremely elementary prototype of an optio-
nally privacy-preserving blockchain based on SMPC (Secure Multi-Party 
Communication).

We make a number of assumptions:
	-First and foremost we assume an existing blockchain architecture
	 although we simulate our own here whereby DECENTRALIZED evaluators
	 can carry out the SMPC function for homomorphic encryption. We
	 model it with a simple eval() method here for simplicity.
	-The blockchain itself stores ALL wallet parameters in encrypted
	 form and can verify them at any time although we store them in a
	 dictionary here for simplicity.
	-We conduct no specific precondition checks for account balances 
	 as that is not what we are illustrating
	-The distributed SMPC system can verify that requested encrypted
	 contracts are based on a formal grammar and does not violate
	 either side's security. This formal grammar is one that can
	 guarantee Turing-Completeness.
	-Upon encrypting and decrypting a transaction on the blockchain we
	 assume that the transaction contract code is directly sent to the
	 recipient who approves it for simplicity although a two-step
	 process of pushing-pulling => pushing-pulling is equally feasible. 
	-For conciseness of demonstration, we chose to keep the hashed
	 values as object addresses instead of actual hash values
	-We assume standard transaction fees are 1 unit for executors and
	 and additional fee in the form of contract code length
'''

#CRYPTOGRAPHY

#generates a private and public RSA key-pair
def generate_RSA(bits=1024):
	key = RSA.generate(bits, e=65537) 
	private_key = key.exportKey('PEM')
	public_key = key.publickey().exportKey('PEM')
	return private_key, public_key

#encrypts a message with a key (public_key can actually be private_key)
def encrypt_key(message, public_key):
    rsa_public_key = RSA.importKey(public_key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted_text = rsa_public_key.encrypt(message)
    return base64.b64encode(encrypted_text)

#decrypts a message with a key (private_key can actually be public_key)
def decrypt_key(encoded_encrypted_msg, private_key):
    rsa_private_key = RSA.importKey(private_key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(base64.b64decode(encoded_encrypted_msg))
    return decrypted_text

#WALLETS

class Wallet:
	#generate a wallet and assign to passed blockchain
	def __init__(self, name, age, blockchain, balance=0, tier=1):
		self.name=name
		self.age=age
		self.blockchain = blockchain
		self.balance=balance
		self.tier=tier
		self.keys=generate_RSA()
		self.private_key=self.keys[0]
		self.public_key=self.keys[1]
		self.blockchain.registered_wallets[str(self.public_key)]=self

	#a publicly visible transfer is a clear transfer
	def clear_transfer(self, address, amount):
		self.balance-=amount
		self.balance-=1
		recipient = self.blockchain.registered_wallets.get(str(address))
		recipient.balance+=amount
		fullDateString = datetime.now().strftime("%H:%M:%S")
	
		#hashed paramters are required for integrity checks in blockchains
		#although this is a simple example here
		textToHash = str(self.public_key)+str(address)+str(amount)+fullDateString
		hashedText = hashlib.sha256(textToHash.encode('utf-8'))
		
		#a return of parameters to register into the blockchain
		return [self.public_key, address, amount, 
			fullDateString, self.name, self.balance, self.blockchain.registered_wallets.get(str(address)).name, self.blockchain.registered_wallets.get(str(address)).balance, hashedText]
		
	#encrypting a smart contract based on a formal and Turing-Complete Grammar
	def encrypt_contract(self, address, contract):
		#a flag to illustrate if a contract is to be decrypted in a transaction
		decrypt_flag = False
		
		#the cost of encrypting a contract
		self.balance-=len(contract) #assume each symbol costs 1 unit to execute
		fullDateString = datetime.now().strftime("%H:%M:%S")
		
		#assume a simple eval() is a decentralized SMPC computation for simplicity
		result_SMPC = [str(x) for x in eval(contract)]
		
		#encrypted result reserved for signer
		encrypted_result_self = encrypt_key(result_SMPC[0].encode('utf-8'), self.public_key)
		#encrypted result reserved for contract sender
		encrypted_result_sender = encrypt_key(result_SMPC[1].encode('utf-8'), address)
		#encrypted contract
		encrypted_contract = encrypt_key(contract.encode('utf-8'), address)
		
		#contract sender
		contract_sender = encrypt_key(self.name.encode('utf-8'), address)
		
		textToHash = str(self.public_key)+str(address)+contract+str(contract_sender)+fullDateString
		hashedText = hashlib.sha256(textToHash.encode('utf-8'))
		
		#encryptedHash to verify on decryption later
		encryptedHash = encrypt_key(str(hashedText).encode('utf-8'), address)
				
		return [encrypted_contract,encrypted_result_self,encrypted_result_sender, contract_sender, hashedText, encryptedHash, decrypt_flag]
	
	#decrypting a transaction
	def decrypt_transaction(self, transaction):
		#fetching an encrypted smart contract
		encrypted_contract = transaction[0]
		#fetching the signer, sender, hash
		encrypted_result_signer = transaction[2]
		encrypted_contract_sender = transaction[3]
		encrypted_hash = transaction[-2]
		decrypt_flag = True
		
		#decrypting the contract, signer result, sender, and hash with RSA
		#assume the sender is a required decryption by the blockchain architecture
		#to guarantee integrity
		decrypted_contract = decrypt_key(encrypted_contract, self.private_key)
		decrypted_result_signer = decrypt_key(encrypted_result_signer, self.private_key)
		decrypted_sender = decrypt_key(encrypted_contract_sender, self.private_key)
		decrypted_hash = decrypt_key(encrypted_hash, self.private_key)
		#once again, transaction price is the length of the decrypted contract
		self.balance-=len(decrypted_contract)
		
		#return all decrypted parameters from prior transaction and register
		#this as a transaction
		return [decrypted_contract, decrypted_result_signer, decrypted_sender, self.name, self.public_key, decrypted_hash, decrypt_flag]
		
#BLOCKCHAIN

class Blockchain:

	#initializing the blockchain
	def __init__(self):
		#every transaction is a block for simplicity; 0 is the genesis block
		self.blocknumber = 0
		#storing the wallets in the blockchain, very naively for simplicity
		self.registered_wallets = {}
		#this is a memory-intensive implementation for illustration purposes
		#we do not, of course, require to store the entire transaction list...
		self.transaction_list = [] 
		
	#"committing" a transaction - we merely place it in the transaction list above
	#in addition to displaying its details
	def commit(self, transaction):
		if(len(transaction)==9):
			#printing clear view transaction details
			print("-"*100)
			print("CLEAR (DECRYPTED) TRANSFER TRANSACTION:")
			print()
			print("**SENDER PUBLIC KEY**:")
			line = transaction[0][27:-28]
			line = "".join([str(x)[2:] for x in line.split("\n".encode())])
			print(line)
			print()
			print("**RECIPIENT PUBLIC KEY**:")
			line = transaction[1][27:-27]
			line = "".join([str(x)[2:] for x in line.split("\n".encode())])
			print(line)
			print()
			print("TRANSACTION AMOUNT:",transaction[2])
			print("TRANSACTION TIME:", transaction[3])
			print("SENDER NAME:", transaction[4])
			print("SENDER BALANCE:",transaction[5])
			print("RECIPIENT NAME:", transaction[6])
			print("RECIPIENT BALANCE:", transaction[7])
			print("TRANSACTION HASH (object):",transaction[8])
			print("BLOCK NUMBER:", self.blocknumber+1)
			print("-"*100)
		else:
			#printing encrypted contract transaction details
			if(transaction[-1]==False):
				print("-"*100)
				print("ENCRYPTED CONTRACT TRANSACTION:")
				print()
				print("ENCRYPTED CONTRACT:",str(transaction[0])[1:])
				print()
				print("ENCRYPTED SIGNER RESULT:", str(transaction[1])[1:])
				print()
				print("ENCRYPTED SENDER RESULT:", str(transaction[2])[1:])
				print()
				print("ENCRYPTED HASH SENDER:", str(transaction[3])[1:])
				print()
				print("TRANSACTION HASH (object):", transaction[4])
				print()
				print("ENCRYPTED HASH:", str(transaction[5])[1:])
				print("BLOCK NUMBER:", self.blocknumber+1)
				print("-"*100)
			else:
				#printing smart contract decryption transaction details
				print("-"*100)
				print("SMART CONTRACT DECRYPTION TRANSACTION:")
				print()
				print("DECRYPTED CONTRACT:",str(transaction[0])[1:])
				print("DECRYPTED SIGNER RESULT:", str(transaction[1])[1:])
				print("DECRYPTED SENDER:", str(transaction[2])[1:])
				print("SIGNER NAME:", "'"+str(transaction[3])+"'")
				line = transaction[4][27:-27]
				line = "".join([str(x)[2:] for x in line.split("\n".encode())])
				print("SIGNER ADDRESS:", line)
				print()
				print("DECRYPTED HASH:", str(transaction[5])[1:])
				print("BLOCK NUMBER:", self.blocknumber+1)
				print("-"*100)	
				
		t = str(transaction) + str(self.blocknumber)
		t += str((hashlib.sha256(t.encode('utf-8'))))
		#hashing all predecessor non-genesis blocks as a requirement to chain
		#all blocks...
		if len(self.transaction_list)>=1:
			t += str(hashlib.sha256(str(self.transaction_list[self.blocknumber-1]).encode('utf-8')))
		self.blocknumber+=1
		self.transaction_list.append(t)
	
	#executing every transaction in the blockchain and committing
	def run(self, transactions):
		for transaction in transactions:
			t = transaction
			self.commit(t)			
			
#BLOCKCHAIN RUN SIMULATED BY MAIN
	
if __name__=="__main__":
	
	#blockchain instance
	simulatedBlockchain = Blockchain()
	
	'''
	WALLET STRUCTURE:
	    NAME
	    AGE
	    BLOCKCHAIN
	    ACCOUNT BALANCE
	    AUTHORITY TIER (THE HIGHER THE MORE AUTHORIZED)
	'''
	#WALLETS FOR SIMULATION	
	alice = Wallet("alice", 25, simulatedBlockchain, 100, 3)
	bob = Wallet("bob", 21, simulatedBlockchain, 64, 1)
	caleb = Wallet("caleb", 22, simulatedBlockchain, 233, 2)
	derek = Wallet("derek", 41, simulatedBlockchain, 812, 1)
	
	#TRANSACTIONS FOR SIMULATION
	
	transaction_1 = (caleb.clear_transfer(bob.public_key, 2))		
	
	
	'''
	Below, Officer Alice Checks if Bob's age >= 21 and allows Bob to verify
	that her public authority tier is greater than his
	'''		
	#smart contract code for encryption			
	contract = '[True,alice.tier>bob.tier] if bob.age>=21 else [False,alice.tier>bob.tier]'
	#full transaction
	transaction_2 = alice.encrypt_contract(bob.public_key, contract)
	
	transaction_3 = (derek.clear_transfer(alice.public_key, 268))
	
	#decrypting transaction 2 by Bob!
	transaction_4 =  bob.decrypt_transaction(transaction_2)
	
	#running all blockchain transactions... this can be even more efficiently
	#demonstrated by threads in a future prototype :)
	transactions=[transaction_1,transaction_2,transaction_3,transaction_4]	
	simulatedBlockchain.run(transactions)
		
		
		
		
		
		
		
	
	
	
	
	
	
	
		
		
	
