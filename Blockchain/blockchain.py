class Block:
	def __init__(self, prevHash, data) -> None:
		self.prev = prevHash
		self.nonce = 0
		self.hash = hash(data)
		self.data = data

	def genHash(self) -> None:
		self.hash = hash((self.data, self.nonce, self.prev))

class BlockNode:
	def __init__(self, block, parent) -> None:
	    self.block = block
	    self.parent = parent
	    self.height = parent.height + 1 if parent != None else 0
	    self.children = []

	def __repr__(self) -> str:
	    return f'data = {self.block.data} hash = {self.block.hash}'

class BlockChain:
	def __init__(self, genesisData) -> None:
		self.root = BlockNode(Block(None, genesisData), None)

	def searchByHash(self, hash :int) -> BlockNode:
		for node in self.getAll():
			if node.block.hash == hash:
				return node
		return None

	def addBlock(self, block :Block) -> None:
		parent = self.searchByHash(block.prev)
		parent.children.append(BlockNode(block, parent))

	def __repr__(self) -> str:
		result = ''
		for node in self.getAll():
			result += '----' * node.height + f'> {node}\n'
		return result

	def getAll(self) -> list:
		nodes, result = [self.root], []
		while len(nodes) > 0:
			node = nodes.pop()
			result.append(node)
			nodes.extend(node.children)
		return result

	def getMaxHeightBlock(self) -> Block:
		return max(self.getAll(), key= lambda x :x.height).block

if __name__ == '__main__':
	bc = BlockChain('0')
	bc.addBlock(Block(bc.getMaxHeightBlock().hash, '1'))
	bc.addBlock(Block(bc.getMaxHeightBlock().hash, '2'))
	bc.addBlock(Block(hash('2'), '3'))
	bc.addBlock(Block(hash('0'), 'alternative data'))
	print(bc)