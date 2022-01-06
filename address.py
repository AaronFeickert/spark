# Address generation

from dumb25519 import Point, Scalar, hash_to_point, random_scalar, hash_to_scalar
import util

class AddressParameters:
	def __init__(self,F,G,index_bytes):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(index_bytes,int) or not index_bytes > 0:
			raise TypeError('Bad type or value for index_bytes!')
		
		self.F = F
		self.G = G
		self.index_bytes = index_bytes

class SpendKey:
	def __init__(self,params):
		if not isinstance(params,AddressParameters):
			raise TypeError('Bad type for parameters!')

		self.params = params
		self.s1 = random_scalar()
		self.s2 = random_scalar()
		self.r = random_scalar()
	
	def full_view_key(self):
		s1 = self.s1
		s2 = self.s2
		D = self.r*self.params.G

		return FullViewKey(self.params,self.base_address(),s1,s2,D)
	
	def incoming_view_key(self):
		s1 = self.s1

		return IncomingViewKey(self.params,self.base_address(),s1)
	
	def base_address(self):
		P2 = self.s2*self.params.F + self.r*self.params.G

		return BaseAddress(P2)
	
	def public_address(self,params,i=0):
		if not isinstance(params,AddressParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(i,int) or not i >= 0:
			raise TypeError('Bad type or value for index!')

		d_bytes = util.chacha(self.s1,i.to_bytes(params.index_bytes,'little'))
		d = int.from_bytes(d_bytes,'little')
		Q1 = self.s1*hash_to_point('Spark Q1',d)
		Q2 = (hash_to_scalar('Q2',self.s1,d) + self.s2)*self.params.F + self.r*self.params.G

		return PublicAddress(d,Q1,Q2)

class FullViewKey:
	def __init__(self,params,base,s1,s2,D):
		if not isinstance(params,AddressParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(base,BaseAddress):
			raise TypeError('Bad type for base address!')
		if not isinstance(s1,Scalar):
			raise TypeError('Bad type for full view key!')
		if not isinstance(s2,Scalar):
			raise TypeError('Bad type for full view key!')
		if not isinstance(D,Point):
			raise TypeError('Bad type for full view key!')
		
		self.params = params
		self.base = base
		self.s1 = s1
		self.s2 = s2
		self.D = D
	
class IncomingViewKey:
	def __init__(self,params,base,s1):
		if not isinstance(params,AddressParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(base,BaseAddress):
			raise TypeError('Bad type for base address!')
		if not isinstance(s1,Scalar):
			raise TypeError('Bad type for incoming view key!')
		if not isinstance(base,BaseAddress):
			raise TypeError('Bad type for base address!')
		
		self.params = params
		self.base = base
		self.s1 = s1
	
	def get_index(self,d):
		i_bytes = util.chacha(self.s1,d.to_bytes(self.params.index_bytes,'little'))
		i = int.from_bytes(i_bytes,'little')

		return i

class BaseAddress:
	def __init__(self,P2):
		if not isinstance(P2,Point):
			raise TypeError('Bad type for base address!')

		self.P2 = P2

class PublicAddress:
	def __init__(self,d,Q1,Q2):
		if not isinstance(d,int) or not d >= 0:
			raise TypeError('Bad type or value for diversifier!')
		if not isinstance(Q1,Point):
			raise TypeError('Bad type for public address!')
		if not isinstance(Q2,Point):
			raise TypeError('Bad type for public address!')

		self.d = d
		self.Q1 = Q1
		self.Q2 = Q2
