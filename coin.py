# Coin structure

from typing import Type
from dumb25519 import Point, Scalar, PointVector, ScalarVector, random_scalar, hash_to_scalar
import address
import bpplus
import schnorr
import util
from enum import Enum

class CoinType(Enum):
	STANDARD = 1 # a coin with hidden recipient and value
	MINT = 1 # a coin with hidden recipient but known value
	PAYOUT = 2 # a deterministic coin with known recipient and value

class CoinParameters:
	def __init__(self,F,G,H,U,value_bytes,memo_bytes):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(U,Point):
			raise TypeError('Bad type for parameter U!')
		if not isinstance(value_bytes,int) or value_bytes < 1:
			raise ValueError('Bad type or value for parameter value_bytes!')
		if not isinstance(memo_bytes,int) or memo_bytes < 1:
			raise ValueError('Bad type or value for parameter memo_bytes!')
		
		self.F = F
		self.G = G
		self.H = H
		self.U = U
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
		if self.type == CoinType.STANDARD:
			return repr(hash_to_scalar(
				self.K,
				self.S,
				self.C,
				self.range,
				self.enc,
				self.janus
			))
		elif self.type == CoinType.MINT:
			return repr(hash_to_scalar(
				self.K,
				self.S,
				self.C,
				self.value,
				self.enc,
				self.janus
			))
		elif self.type == CoinType.PAYOUT:
			return repr(hash_to_scalar(
				self.K,
				self.S,
				self.C,
				self.value
			))

	def __init__(self,params,public,value,memo,type,is_output,k=None):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for coin address!')
		if not isinstance(value,int) or value < 0 or value.bit_length() > 8*params.value_bytes:
			raise ValueError('Bad type or value for coin value!')
		if not isinstance(memo,str) or len(memo.encode('utf-8')) > params.memo_bytes:
			raise ValueError('Bad type or size for coin memo!')
		if not isinstance(type,CoinType):
			raise TypeError('Bad type for coin type!')
		if not isinstance(is_output,bool):
			raise TypeError('Bad type for coin output flag!')

		# Standard and mint coins use a randomly-derived recovery key
		if type in [CoinType.STANDARD,CoinType.MINT] and k is None:
			k = random_scalar()
		# Payout coins use a deterministic recovery key
		if type == CoinType.PAYOUT and (not isinstance(k,Scalar) or k is None):
			raise TypeError('Payout coins must have deterministic recovery!')

		# Recovery key
		self.K = k*public.Q0
		K_der = k*public.Q1

		# Serial number and value commitments
		self.S = hash_to_scalar('ser',K_der)*params.F + public.Q2
		self.C = Scalar(value)*params.G + hash_to_scalar('val',K_der)*params.H

		# Standard coins have range proofs
		if type == CoinType.STANDARD:
			self.range = bpplus.prove(
				bpplus.RangeStatement(bpplus.RangeParameters(params.G,params.H,8*params.value_bytes),PointVector([self.C])),
				bpplus.RangeWitness(ScalarVector([Scalar(value)]),ScalarVector([hash_to_scalar('val',K_der)]))
			)
		
		# Standard and mint coins have diversifier proofs
		if type in [CoinType.STANDARD,CoinType.MINT]:
			self.janus = schnorr.prove(
				schnorr.SchnorrStatement(schnorr.SchnorrParameters(params.F),k*params.F),
				schnorr.SchnorrWitness(k)
			)

		# Prepare recipient data for encryption
		padded_memo = memo.encode('utf-8')
		padded_memo += bytearray(params.memo_bytes - len(padded_memo))
		aead_key = hash_to_scalar('aead',K_der)

		# Standard coins have an encrypted value and memo
		if type == CoinType.STANDARD:
			padded_value = value.to_bytes(params.value_bytes,'little')
			self.enc = util.aead_encrypt(aead_key,'Spend recipient data',padded_value + padded_memo)
		# Mint coins have an encrypted memo
		elif type == CoinType.MINT:
			self.value = value
			self.enc = util.aead_encrypt(aead_key,'Mint recipient data',padded_memo)
		# Payout coins have no encrypted recipient data
		elif type == CoinType.PAYOUT:
			self.value = value

		# Data used for output only
		self.is_output = False
		if is_output:
			self.is_output = True
			self.k = k
			self.Q1 = public.Q1
			self.value = value
		
		self.diversifier = None
		self.identified = False
		self.recovered = False
		self.type = type
	
	def identify(self,params,incoming):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(incoming,address.IncomingViewKey):
			raise TypeError('Bad type for incoming view key!')
	
		K_der = incoming.s1*self.K
		
		# Get the diversifier and associate to the address
		Q2 = self.S - hash_to_scalar('ser',K_der)*params.F
		try:
			self.diversifier = incoming.get_diversifier(Q2)
			
			# Standard and mint coins require a diversifier proof; payout coins don't need this since they are deterministic
			if self.type in [CoinType.STANDARD,CoinType.MINT]:
				schnorr.verify(
					schnorr.SchnorrStatement(schnorr.SchnorrParameters(params.F),hash_to_scalar('Q0',incoming.s1,self.diversifier).invert()*self.K),
					self.janus
				)
		except:
			raise ArithmeticError('Coin does not belong to this public address!')
	
		# Prepare decryption key
		aead_key = hash_to_scalar('aead',K_der)

		# Standard coins have encrypted value and memo
		if self.type == CoinType.STANDARD:
			data_bytes = util.aead_decrypt(aead_key,'Spend recipient data',self.enc)
			if data_bytes is not None:
				self.value = int.from_bytes(data_bytes[:params.value_bytes],'little')
				self.memo = data_bytes[params.value_bytes:].decode('utf-8').rstrip('\x00')
			else:
				raise ArithmeticError('Bad recipient data!')
		# Mint coins have encrypted memo
		elif self.type == CoinType.MINT:
			memo_bytes = util.aead_decrypt(aead_key,'Mint recipient data',self.enc)
			if memo_bytes is not None:
				self.memo = memo_bytes.decode('utf-8').rstrip('\x00')
			else:
				raise ArithmeticError('Bad recipient data!')

		# Test for value commitment
		if not self.C == Scalar(self.value)*params.G + hash_to_scalar('val',K_der)*params.H:
			raise ArithmeticError('Bad coin value commitment!')
		
		# Standard coins need to verify the range proof
		if self.type == CoinType.STANDARD:
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
		
		# Recover serial number and generate tag
		K_der = full.s1*self.K
		self.s = hash_to_scalar('ser',K_der) + hash_to_scalar('Q2',full.s1,self.diversifier) + full.s2
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
	
	def verify(self,params,public,k):
		if not isinstance(params,CoinParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for coin address!')
		if not isinstance(k,Scalar):
			raise TypeError('Bad type for deterministic recovery key preimage!')

		# Only payout coins can be verified in this way
		if not self.type == CoinType.PAYOUT:
			raise TypeError('Cannot verify non-payout coin!')

		# Check value
		if self.value < 0 or self.value.bit_length() > 8*params.value_bytes:
			raise ValueError('Bad value for coin value!')
		
		# Check the recovery key
		if not self.K == k*public.Q0:
			raise ValueError('Bad recovery key verification!')
		
		# Serial number and value commitments
		K_der = k*public.Q1
		if not self.S == hash_to_scalar('ser',K_der)*params.F + public.Q2:
			raise ValueError('Bad serial commitment verification!')
		if not self.C == Scalar(self.value)*params.G + hash_to_scalar('val',K_der)*params.H:
			raise ValueError('Bad value commitment verification!')
