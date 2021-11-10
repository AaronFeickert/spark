# Payout transaction

import address
import coin
from dumb25519 import Point, Scalar, hash_to_scalar
import pay
import schnorr

class ProtocolParameters:
	def __init__(self,F,G,H,U,value_bytes,memo_bytes):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(U,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(value_bytes,int) or value_bytes < 1:
			raise ValueError('Bad type or value for parameter value_bytes!')
		if not isinstance(memo_bytes,int) or memo_bytes < 1:
			raise ValueError('Bad type or value for parameter value_bytes!')
		
		self.F = F
		self.G = G
		self.H = H
		self.U = U
		self.value_bytes = value_bytes
		self.memo_bytes = memo_bytes

class PayoutTransaction:
	def __init__(self,params,public,value):
		if not isinstance(params,ProtocolParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(public,address.PublicAddress):
			raise TypeError('Bad type for delegation key!')
		if not isinstance(value,int) or value < 0 or value.bit_length() > 8*params.value_bytes:
			raise ValueError('Bad type or value for coin value!')
		
		# Generate coin with known address and value
		self.public = public
		self.output = coin.Coin(
			coin.CoinParameters(params.F,params.G,params.H,params.U,params.value_bytes,params.memo_bytes),
			public,
			value,
			'',
			True,
			True
		)
		self.value = value

		# Assert address
		self.K_der = self.output.k*self.output.Q1
		self.K_div = self.output.k*params.F
		self.proof = pay.prove(
			pay.PayStatement(
				pay.PayParameters(params.F,params.G,params.H,params.value_bytes),
				'Payout',
				self.output,
				self.K_der,
				self.K_div,
				self.public
			),
			pay.PayWitness(self.output.k)
		)

	def verify(self,params):
		if not isinstance(params,ProtocolParameters):
			raise TypeError('Bad type for parameters!')

		# Check value range
		if self.value < 0 or self.value.bit_length() > 8*params.value_bytes:
			raise ValueError('Bad value for coin value!')
		
		# Check address and value
		pay.verify(
			pay.PayStatement(
				pay.PayParameters(params.F,params.G,params.H,params.value_bytes),
				'Payout',
				self.output,
				self.K_der,
				self.K_div,
				self.public
			),
			self.proof
		)
