from blockchain import Block, BlockChain, BlockNode
import rsa

class Transaction:
	def __init__(self, sellerPk, buyerPk, homeNum) -> None:
		self.seller = sellerPk
		self.receiver = buyerPk
		self.num = homeNum
		self.signature = None

	def sign(self, sk) -> None:
		encoded = f'{self.seller}{self.receiver}{self.num}'.encode()
		self.signature = rsa.sign(encoded, sk, 'SHA-1')
	
	def verify(self) -> bool:
		encoded = f'{self.seller}{self.receiver}{self.num}'.encode()
		return rsa.verify(encoded, self.signature, self.seller)

	def __repr__(self) -> str:
	    return f'from {self.seller} to {self.receiver}\nhouse number = {self.num}\n'

def checkMarket(bc :BlockChain) -> dict:
	node = bc.root
	result = dict()
	while True:
		for tx in node.block.data:
			if tx.verify():
				result[tx.num] = tx.receiver
		if len(node.children) < 1:
			break
		node = max(node.children, key= lambda x: x.height)
	return result

def mineBlock(bc :BlockChain, data :tuple) -> None:
	block = Block(bc.getMaxHeightBlock().hash, data)
	n = 0
	while True:
		block.nonce = n
		block.genHash()
		if str(block.hash)[-2:] == '00':
			break
		n += 1
	bc.addBlock(block)

agents = [rsa.newkeys(512) for n in range(5)]

(ownerPk, ownerSk) = rsa.newkeys(512)
genesisData = []
for num, keyPair in enumerate(agents):
	tx = Transaction(ownerPk, keyPair[0], num)
	tx.sign(ownerSk)
	genesisData.append(tx)

bc = BlockChain(tuple(genesisData))
tx = Transaction(agents[0][0], agents[1][0], 0)
tx.sign(agents[0][1])
for k, v in checkMarket(bc).items():
	print(f'house number = {k}, receiver = {v}')
mineBlock(bc, tuple([tx]))
print('transaction mined!')
for k, v in checkMarket(bc).items():
	print(f'house number = {k}, receiver = {v}')