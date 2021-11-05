# Asynchronous multisignature algorithms using FROST-like techniques
#
# Uses the more efficient method from https://eprint.iacr.org/2021/1375

from dumb25519 import *
import asyncio

# Public generators
F = hash_to_point('F')
H = hash_to_point('H')
U = hash_to_point('U')

# Compute Lagrange coefficients
def lagrange(i,indexes):
	coeff = Scalar(1)
	for j in indexes:
		if j == i:
			continue
		coeff *= Scalar(j)*(Scalar(j) - Scalar(i)).invert()
	return coeff

def challenge(statement,A1,A2):
	return hash_to_scalar('Spark challenge',F,G,H,U,statement.m,statement.S,statement.T,A1,A2)

class SigningStatement:
	def __init__(self,m,S,T):
		self.m = m
		self.S = S
		self.T = T

class SigningWitness:
	def __init__(self,x,z):
		self.x = x
		self.z = z

class Player:
	def __init__(self,alpha,nu,t):
		self.alpha = alpha # player identifier
		self.nu = nu # total players
		self.t = t # signing threshold

		# Key generation round 1
		self.C = {}
		self._s1 = {}
		self._s2 = {}

		# Key generation round 2
		self.r_hat = {}

		# Precomputation
		self.l = []
		self.L = {}

		# Signing
		self.signers = []
		self._t2 = {}

	def set_neighbors(self,neighbors):
		self.neighbors = {}

		if not type(neighbors) is dict:
			raise TypeError
		if not len(neighbors) == self.nu:
			raise IndexError
		for beta in range(1,self.nu+1):
			if beta not in neighbors:
				raise IndexError
			if not isinstance(neighbors[beta],Player):
				raise TypeError
			if beta != self.alpha:
				self.neighbors[beta] = neighbors[beta]
		
	async def keygen(self):
		# Coefficients
		self.a = [random_scalar() for _ in range(self.t)]

		# View key shares
		self._s1[self.alpha] = random_scalar()
		self._s2[self.alpha] = random_scalar()

		# Proof of knowledge
		k = random_scalar()
		R = k*G
		c = hash_to_scalar('Spark multisig keygen',self.alpha,self.a[0]*G,R)
		mu = k + self.a[0]*c

		# Coefficient commitments
		self.C[self.alpha] = [self.a[j]*G for j in range(self.t)]

		# Send to other players
		tasks = [asyncio.ensure_future(self.neighbors[beta].get_keygen_1(self.alpha,R,mu,self.C[self.alpha],self._s1[self.alpha],self._s2[self.alpha])) for beta in self.neighbors]
		await asyncio.wait(tasks)
		
		# Wait for all other players
		while not self.keygen_1_complete():
			await asyncio.sleep(0)

		# Generate secret shares
		r_hat = {}
		for beta in range(1,self.nu+1):
			temp = Scalar(0)
			for j in range(self.t):
				temp += self.a[j]*beta**j
			
			r_hat[beta] = temp
		self.r_hat[self.alpha] = r_hat[self.alpha]
		
		# Send to other players
		tasks = [asyncio.ensure_future(self.neighbors[beta].get_keygen_2(self.alpha,r_hat[beta])) for beta in self.neighbors]
		await asyncio.wait(tasks)

		# Wait for all other players
		while not self.keygen_2_complete():
			await asyncio.sleep(0)
		
		# Compute signing share
		self.r = Scalar(0)
		for beta in range(1,self.nu+1):
			self.r += self.r_hat[beta]
		
		# Compute the group keys
		self.D = Z
		for beta in range(1,self.nu+1):
			self.D += self.C[beta][0]
		_s1 = [self._s1[beta] for beta in sorted(self._s1)]
		_s2 = [self._s1[beta] for beta in sorted(self._s1)]
		self.s1 = hash_to_scalar('Spark s1',_s1)
		self.s2 = hash_to_scalar('Spark s2',_s2)
		
	async def get_keygen_1(self,beta,R,mu,C,s1,s2):
		# Verify the proof
		if not mu*G - hash_to_scalar('Spark multisig keygen',beta,C[0],R)*C[0] == R:
			raise ArithmeticError
		
		# Store the neighbor's data
		self.C[beta] = C
		self._s1[beta] = s1
		self._s2[beta] = s2
	
	async def get_keygen_2(self,beta,r_hat):
		# Verify the share
		r_hat_G = Z
		for j in range(self.t):
			r_hat_G += Scalar(self.alpha**j)*self.C[beta][j]
		if not r_hat_G == r_hat*G:
			raise ArithmeticError
		
		# Store the neighbor's data
		self.r_hat[beta] = r_hat
	
	# The round is complete when we have received all neighbor data
	def keygen_1_complete(self):
		indexes = set(self.neighbors.keys())
		indexes.add(self.alpha)

		for check in [self.C,self._s1,self._s2]:
			if not set(check) == indexes:
				return False
		
		return True
	
	# The round is complete when we have received all neighbor data
	def keygen_2_complete(self):
		indexes = set(self.neighbors.keys())
		indexes.add(self.alpha)

		if not set(self.r_hat) == indexes:
			return False
		
		return True
	
	async def precompute(self):
		# Generate nonce
		d = random_scalar()
		D = d*G
		e = random_scalar()
		E = e*G

		self.l.append((d,e))
		if self.alpha not in self.L:
			self.L[self.alpha] = [(D,E)]
		else:
			self.L[self.alpha].append((D,E))

		# Send to other players
		tasks = [asyncio.ensure_future(self.neighbors[beta].get_precompute(self.alpha,D,E)) for beta in self.neighbors]
		await asyncio.wait(tasks)

		# Wait for all other players
		while not self.precompute_complete():
			await asyncio.sleep(0)
	
	async def get_precompute(self,beta,D,E):
		# Check for nonce validity
		if D == Z or E == Z:
			raise ValueError

		# Store the neighbor's data
		if beta not in self.L:
			self.L[beta] = [(D,E)]
		else:
			self.L[beta].append((D,E))
	
	def precompute_complete(self):
		indexes = set(self.neighbors.keys())
		indexes.add(self.alpha)

		if not set(self.L) == indexes:
			return False
		for beta in self.L:
			if not len(self.L[beta]) == len(self.l):
				return False
		
		return True
	
	def nonce_hash(self):
		rho = []
		for u in range(len(self.statement.S)):
			nonce_D = [self.L[beta][-1-u][0] for beta in self.signers]
			nonce_E = [self.L[beta][-1-u][1] for beta in self.signers]

			rho.append(hash_to_scalar('Spark multisig nonce hash',self.statement.m,self.statement.S[u],self.statement.T[u],self.signers,nonce_D,nonce_E))
		
		return rho

	async def sign(self,signers,statement,witness):
		# This player must be a signer
		if not self.alpha in signers:
			raise IndexError

		self.signers = sorted(signers)
		self.statement = statement
		w = len(self.statement.S)
		
		# Prepare binders
		rho = self.nonce_hash()
		rho_F_T = [hash_to_scalar('Spark multisig F/T',rho[u]) for u in range(w)]
		rho_H = [hash_to_scalar('Spark multisig H',rho[u]) for u in range(w)]

		# Compute initial proof statements
		A1 = Z
		A2 = []
		for u in range(w):
			A1 += rho_F_T[u]*F + rho_H[u]*H
			A2.append(rho_F_T[u]*statement.T[u])

			for beta in self.signers:
				(D,E) = self.L[beta][-1-u]
				A1 += D + rho[u]*E
				A2[u] += D + rho[u]*E
		
		self.A1 = A1
		self.A2 = A2
		
		# Challenge
		c = challenge(statement,A1,A2)
		
		# Responses
		self.t1 = []
		self._t2[self.alpha] = Scalar(0)
		self.t3 = Scalar(0)
		for u in range(w):
			(d,e) = self.l[-1-u]
			self.t1.append(rho_F_T[u] + c**u*witness.x[u])
			self._t2[self.alpha] += d + rho[u]*e + lagrange(self.alpha,self.signers)*self.r*c**u
			self.t3 += rho_H[u] + c**u*witness.z[u]

		# Send to other players
		tasks = [asyncio.ensure_future(self.neighbors[beta].get_sign(self.alpha,self._t2[self.alpha])) for beta in signers if beta != self.alpha]
		await asyncio.wait(tasks)

		# Wait for all other players
		while not self.sign_complete():
			await asyncio.sleep(0)
		
		# Aggregate the signature
		self.t2 = Scalar(0)
		for beta in self.signers:
			self.t2 += self._t2[beta]
	
	async def get_sign(self,beta,t2):
		# Verify the response
		Y = Z
		for gamma in range(1,self.nu+1):
			for j in range(self.t):
				Y += Scalar(beta**j)*self.C[gamma][j]
		
		R = Z
		c = challenge(self.statement,self.A1,self.A2)
		lambd = lagrange(beta,self.signers)
		for u in range(len(self.statement.S)):
			(D,E) = self.L[beta][-1-u]
			rho = self.nonce_hash()
			R += D + rho[u]*E + c**u*lambd*Y
		if not t2*G == R:
			raise ArithmeticError
		
		# Store the neighbor's data
		self._t2[beta] = t2

	# The round is complete when we have received all neighbor data
	def sign_complete(self):
		indexes = set(self.signers)

		if not set(self._t2) == indexes:
			return False
		
		return True
