# Stake transaction

import address
import chaum
import coin
from dumb25519 import Point, Scalar, PointVector, hash_to_scalar
import parallel
import schnorr

class ProtocolParameters:
	def __init__(self,F,G,H,U,value_bytes,n,m,stake):
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
		if not isinstance(n,int) or n < 1:
			raise ValueError('Bad type or value for parameter n!')
		if not isinstance(m,int) or m < 1:
			raise ValueError('Bad type or value for parameter m!')
		if not isinstance(stake,int) or stake < 0:
			raise ValueError('Bad type or value for parameter stake!')
		
		self.F = F
		self.G = G
		self.H = H
		self.U = U
		self.value_bytes = value_bytes
		self.n = n
		self.m = m
		self.stake = stake

class StakeTransaction:
	def __init__(self,params,full,spend,inputs,l,fee):
		if not isinstance(params,ProtocolParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(full,address.FullViewKey):
			raise TypeError('Bad type for full view key!')
		if not isinstance(spend,address.SpendKey):
			raise TypeError('Bad type for spend key!')
		for input in inputs:
			if not isinstance(input,coin.Coin):
				raise TypeError('Bad type for input coin!')
		if not isinstance(l,int) or l < 0 or l >= params.n**params.m:
			raise ValueError('Bad type or value for spend index!')
		if not inputs[l].recovered:
			raise ValueError('Input coin is not recovered!')
		if not isinstance(fee,int) or fee < 0 or fee.bit_length() > params.value_bytes:
			raise ValueError('Bad type or value for fee!')

		self.inputs = inputs # input cover set
		self.fee = fee # transaction fee

		input = inputs[l]

		# Serial number commitment offset
		self.S1 = input.delegation.S1
		self.C1 = input.delegation.C1

		# Tag
		self.T = input.T

		# Parallel one-of-many proof
		self.parallel = parallel.prove(
			parallel.ParallelStatement(
				parallel.ParallelParameters(params.H,params.n,params.m),
				PointVector([input.S for input in inputs]),
				PointVector([input.C for input in inputs]),
				self.S1,
				self.C1
			),
			parallel.ParallelWitness(
				l,
				input.delegation.s1,
				input.delegation.c1,
			)
		)

		# Value proof
		b_st = self.C1 - Scalar(fee)*params.G - Scalar(params.stake)*params.G
		b_w = hash_to_scalar('val1',input.delegation.id,input.s,full.s1,full.s2)
		self.balance = schnorr.prove(
			schnorr.SchnorrStatement(schnorr.SchnorrParameters(params.H),b_st),
			schnorr.SchnorrWitness(b_w)
		)

		# Modified Chaum-Pedersen proof
		mu = hash_to_scalar(
			'Spark stake proof',
			self.inputs,
			self.fee,
			self.S1,
			self.C1,
			self.T,
			self.parallel,
			self.balance
		)

		self.chaum = chaum.prove(
			chaum.ChaumStatement(chaum.ChaumParameters(params.F,params.G,params.H,params.U),mu,self.S1,self.T),
			chaum.ChaumWitness(input.s,spend.r,Scalar(0) - hash_to_scalar('ser1',input.delegation.id,input.s,full.s1,full.s2))
		)
		

	def verify(self,params,tags=None):
		if not isinstance(params,ProtocolParameters):
			raise TypeError('Bad type for parameters!')

		# Check tag uniqueness
		if tags is not None and self.T in tags:
			raise ValueError('Tag has been seen before!')

		# Check fee
		if self.fee < 0 or self.fee.bit_length() > params.value_bytes:
			raise ValueError('Bad value for transaction fee!')
		
		mu = hash_to_scalar(
			'Spark stake proof',
			self.inputs,
			self.fee,
			self.S1,
			self.C1,
			self.T,
			self.parallel,
			self.balance
		)

		# Check input proof
		parallel.verify(
			parallel.ParallelStatement(
				parallel.ParallelParameters(params.H,params.n,params.m),
				PointVector([input.S for input in self.inputs]),
				PointVector([input.C for input in self.inputs]),
				self.S1,
				self.C1
			),
			self.parallel
		)

		chaum.verify(
			chaum.ChaumStatement(chaum.ChaumParameters(params.F,params.G,params.H,params.U),mu,self.S1,self.T),
			self.chaum
		)
		
		# Check value
		b_st = self.C1 - Scalar(self.fee)*params.G - Scalar(params.stake)*params.G

		schnorr.verify(
			schnorr.SchnorrStatement(schnorr.SchnorrParameters(params.H),b_st),
			self.balance
		)
