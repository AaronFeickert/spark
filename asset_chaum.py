# Aggregated asset Chaum proving system

from random import random
from dumb25519 import Z, Point, PointVector, Scalar, ScalarVector, hash_to_scalar, random_scalar
import transcript

class ChaumParameters:
	def __init__(self,F,G,H):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		
		self.F = F
		self.G = G
		self.H = H

class ChaumStatement:
	def __init__(self,params,C):
		if not isinstance(params,ChaumParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(C,PointVector):
			raise TypeError('Bad type for Chaum statement input C!')
		if not len(C) > 1:
			raise ValueError('Not enough commitments for Chaum statement!')
		
		self.F = params.F
		self.G = params.G
		self.H = params.H
		self.C = C

class ChaumWitness:
	def __init__(self,x,y,z):
		if not isinstance(x,ScalarVector):
			raise TypeError('Bad type for Chaum witness x!')
		if not isinstance(y,ScalarVector):
			raise TypeError('Bad type for Chaum witness y!')
		if not isinstance(z,Scalar):
			raise TypeError('Bad type for Chaum witness z!')
		if not len(x) == len(y):
			raise ValueError('Size mismatch for Chaum witness!')
		
		self.x = x
		self.y = y
		self.z = z

class ChaumProof:
	def __repr__(self):
		return repr(hash_to_scalar(
			self.A,
			self.B,
			self.tx,
			self.ty,
			self.tz,
			self.ux,
			self.uy
		))

	def __init__(self,A,B,tx,ty,tz,ux,uy):
		if not isinstance(A,Point):
			raise TypeError('Bad type for Chaum proof element A!')
		if not isinstance(B,Point):
			raise TypeError('Bad type for Chaum proof element B!')
		if not isinstance(tx,Scalar):
			raise TypeError('Bad type for Chaum proof element tx!')
		if not isinstance(ty,Scalar):
			raise TypeError('Bad type for Chaum proof element ty!')
		if not isinstance(tz,Scalar):
			raise TypeError('Bad type for Chaum proof element tz!')
		if not isinstance(ux,Scalar):
			raise TypeError('Bad type for Chaum proof element ux!')
		if not isinstance(uy,Scalar):
			raise TypeError('Bad type for Chaum proof element uy!')

		self.A = A
		self.B = B
		self.tx = tx
		self.ty = ty
		self.tz = tz
		self.ux = ux
		self.uy = uy

def challenge(statement,A,B):
	if not isinstance(statement,ChaumStatement):
		raise TypeError('Bad type for Chaum statement!')
	if not isinstance(A,Point):
		raise TypeError('Bad type for challenge input A!')
	if not isinstance(B,Point):
		raise TypeError('Bad type for challenge input B!')

	tr = transcript.Transcript('Asset Chaum')
	tr.update(statement.F)
	tr.update(statement.G)
	tr.update(statement.H)
	tr.update(statement.C)
	tr.update(A)
	tr.update(B)
	return tr.challenge()

def prove(statement,witness):
	if not isinstance(statement,ChaumStatement):
		raise TypeError('Bad type for Chaum statement!')
	if not isinstance(witness,ChaumWitness):
		raise TypeError('Bad type for Chaum witness!')
	
	n = len(statement.C)
	
	# Check the statement validity
	for i in range(n):
		if not statement.C[i] == witness.x[i]*statement.F + witness.y[i]*statement.G + witness.z*statement.H:
			raise ArithmeticError('Invalid Chaum statement!')
	
	rx = random_scalar()
	ry = random_scalar()
	rz = random_scalar()
	sx = random_scalar()
	sy = random_scalar()

	A = rx*statement.F + ry*statement.G + rz*statement.H
	B = sx*statement.F + sy*statement.G

	c = challenge(statement,A,B)

	tx = rx + c*witness.x[0]
	ty = ry + c*witness.y[0]
	tz = rz + c*witness.z
	ux = sx
	uy = sy
	for i in range(1,n):
		ux += c**i*(witness.x[i] - witness.x[0])
		uy += c**i*(witness.y[i] - witness.y[0])

	return ChaumProof(A,B,tx,ty,tz,ux,uy)

def verify(statement,proof):
	if not isinstance(statement,ChaumStatement):
		raise TypeError('Bad type for Chaum statement!')
	if not isinstance(proof,ChaumProof):
		raise TypeError('Bad type for Chaum proof!')
	
	n = len(statement.C)
	
	c = challenge(statement,proof.A,proof.B)

	# Assert representation for the first commitment
	if not proof.tx*statement.F + proof.ty*statement.G + proof.tz*statement.H == c*statement.C[0] + proof.A:
		raise ArithmeticError('Failed Chaum verification!')
	
	# Assert equality of other commitments' discrete logarithms
	L = proof.ux*statement.F + proof.uy*statement.G
	R = proof.B
	for i in range(1,n):
		R += c**i*(statement.C[i] - statement.C[0])
	if not L == R:
		raise ArithmeticError('Failed Chaum verification!')
