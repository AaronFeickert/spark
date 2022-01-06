# Coin structure

from dumb25519 import Point, Scalar, PointVector, ScalarVector, hash_to_point, random_scalar, hash_to_scalar
import address
import bpplus
import schnorr
import util

class CoinParameters:
	def __init__(self,F,G,H,U,index_bytes,value_bytes,memo_bytes):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(U,Point):
			raise TypeError('Bad type for parameter U!')
		if not isinstance(index_bytes,int) or index_bytes < 1:
			raise ValueError('Bad type or value for parameter index_bytes!')
		if not isinstance(value_bytes,int) or value_bytes < 1:
			raise ValueError('Bad type or value for parameter value_bytes!')
		if not isinstance(memo_bytes,int) or memo_bytes < 1:
			raise ValueError('Bad type or value for parameter memo_bytes!')
		
		self.F = F
		self.G = G
		self.H = H
		self.U = U
		self.index_bytes = index_bytes
		self.value_bytes = value_bytes
		self.memo_bytes = memo_bytes

class CoinDelegation:
	def __init__(self,id,s1,S1,c1,C1):
		if not isinstance(s1,Scalar):
			raise TypeError('Bad type for parameter s1!')
		if not isinstance(S1,Point):
			raise TypeError('Bad type for parameter S1!')
		if not isinstance(c1,Scalar):
			raise TypeError('Bad type for parameter c1!')
		if not isinstance(C1,Point):
			raise TypeError('Bad type for parameter C1!')
		
		self.id = id
		self.s1 = s1
		self.S1 = S1
		self.c1 = c1
		self.C1 = C1

class Coin:
	def __repr__(self):
		if self.is_mint:
			return repr(hash_to_scalar(
				self.K,
				self.S,
				self.C,
				self.value,
				self.enc,
				self.view_tag
			))
		else:
			return repr(hash_to_scalar(
				self.K,
				self.S,
				self.C,
				self.range,
				self.enc,
				self.view_tag
			))

	def __init__(self,params,public,value,memo,is_mint,is_output):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for coin address!')
		if not isinstance(value,int) or value < 0 or value.bit_length() > 8*params.value_bytes:
			raise ValueError('Bad type or value for coin value!')
		if not isinstance(memo,str) or len(memo.encode('utf-8')) > params.memo_bytes:
			raise ValueError('Bad type or size for coin memo!')
		if not isinstance(is_mint,bool):
			raise TypeError('Bad type for coin mint flag!')
		if not isinstance(is_output,bool):
			raise TypeError('Bad type for coin output flag!')

		# Coin seed
		rho = random_scalar()
			
		# Recovery key and shared secret
		k = hash_to_scalar('Spark k',rho)
		self.K = k*hash_to_point('Spark diversifier',public.d)
		shared = k*public.Q1

		# View tag
		self.view_tag = util.view_tag(shared)

		# Serial number commitment
		self.S = hash_to_scalar('ser',rho)*params.F + public.Q2

		# Value commitment
		self.C = Scalar(value)*params.G + hash_to_scalar('val',rho)*params.H
		if not is_mint:
			self.range = bpplus.prove(
				bpplus.RangeStatement(bpplus.RangeParameters(params.G,params.H,8*params.value_bytes),PointVector([self.C])),
				bpplus.RangeWitness(ScalarVector([Scalar(value)]),ScalarVector([hash_to_scalar('val',rho)]))
			)
		
		# Encrypt recipient data
		diversifier_bytes = public.d.to_bytes(params.index_bytes,'little')
		rho_bytes = bytes.fromhex(repr(rho))[:16]
		memo_bytes = memo.encode('utf-8')
		memo_bytes += bytearray(params.memo_bytes - len(memo_bytes))
		aead_key = hash_to_scalar('aead',shared)
		if is_mint:
			self.value = value
			self.enc = util.aead_encrypt(aead_key,'Mint recipient data',diversifier_bytes + rho_bytes + memo_bytes)
		else:
			value_bytes = value.to_bytes(params.value_bytes,'little')
			self.enc = util.aead_encrypt(aead_key,'Spend recipient data',diversifier_bytes + rho_bytes + value_bytes + memo_bytes)

		# Data used for output only
		self.is_output = False
		if is_output:
			self.is_output = True
			self.rho = rho
			self.public = public
			self.value = value

		self.diversifier = None
		self.identified = False
		self.recovered = False
		self.is_mint = is_mint
	
	def identify(self,params,incoming):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(incoming,address.IncomingViewKey):
			raise TypeError('Bad type for incoming view key!')
	
		# Shared secret
		shared = incoming.s1*self.K
		
		# View tag
		if util.view_tag(shared) != self.view_tag:
			raise ArithmeticError('View tag does not match!')

		# Decrypt recipient data
		aead_key = hash_to_scalar('aead',shared)
		if self.is_mint:
			data_bytes = util.aead_decrypt(aead_key,'Mint recipient data',self.enc)
			if data_bytes is not None:
				cursor = 0
				self.diversifier = int.from_bytes(data_bytes[cursor:cursor+params.index_bytes],'little')
				cursor += params.index_bytes
				self.rho = Scalar(int.from_bytes(data_bytes[cursor:cursor+32],'little'))
				cursor += 32
				self.memo = data_bytes[cursor:].decode('utf-8').rstrip('\x00')
			else:
				raise ArithmeticError('Bad recipient data!')
		else:
			data_bytes = util.aead_decrypt(aead_key,'Spend recipient data',self.enc)
			if data_bytes is not None:
				cursor = 0
				self.diversifier = int.from_bytes(data_bytes[cursor:cursor+params.index_bytes],'little')
				cursor += params.index_bytes
				self.rho = Scalar(int.from_bytes(data_bytes[cursor:cursor+32],'little'))
				cursor += 32
				self.value = int.from_bytes(data_bytes[cursor:cursor+params.value_bytes],'little')
				cursor += params.value_bytes
				self.memo = data_bytes[cursor:].decode('utf-8').rstrip('\x00')
			else:
				raise ArithmeticError('Bad recipient data!')
		
		# Confirm coin construction
		k = hash_to_scalar('Spark k',self.rho)
		if not self.K == k*hash_to_point('Spark diversifier',self.diversifier):
			raise ArithmeticError('Bad coin construction!')
		if not self.S == hash_to_scalar('ser',self.rho)*params.F + incoming.base.P2:
			raise ArithmeticError('Bad coin construction!')
		if not self.C == Scalar(self.value)*params.G + hash_to_scalar('val',shared)*params.H:
			raise ArithmeticError('Bad coin value commitment!')
		
		# Test range proof
		if not self.is_mint:
			bpplus.verify(
				[bpplus.RangeStatement(bpplus.RangeParameters(params.G,params.H,8*params.value_bytes),PointVector([self.C]))],
				[self.range]
			)
		
		self.identified = True
		
	def recover(self,params,full):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for coin parameters!')
		if not isinstance(full,address.FullViewKey):
			raise TypeError('Bad type for full view key!')
		
		# The coin must be identified
		if not self.identified:
			raise ArithmeticError('Coin has not been identified!')
		
		# Shared secret
		shared = full.s1*self.K
		
		# Recover serial number and generate tag
		self.s = hash_to_scalar('ser',shared) + hash_to_scalar('Q2',full.s1,self.diversifier) + full.s2
		self.T = self.s.invert()*(params.U - full.D)

		self.recovered = True
	
	def delegate(self,params,full,id):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for coin parameters!')
		if not isinstance(full,address.FullViewKey):
			raise TypeError('Bad type for full view key!')
		if not self.recovered:
			raise ValueError('Delegation requires coin recovery!')
		
		s1 = hash_to_scalar('ser1',id,self.s,full.s1,full.s2)
		S1 = self.s*params.F - hash_to_scalar('ser1',id,self.s,full.s1,full.s2)*params.H + full.D
		c1 = hash_to_scalar('val',full.s1*self.K) - hash_to_scalar('val1',id,self.s,full.s1,full.s2)
		C1 = Scalar(self.value)*params.G + hash_to_scalar('val1',id,self.s,full.s1,full.s2)*params.H

		self.delegation = CoinDelegation(id,s1,S1,c1,C1)
