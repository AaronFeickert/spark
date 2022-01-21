# Address generation

from dumb25519 import Point, hash_to_point, random_scalar, hash_to_scalar
import util

class AddressParameters:
	def __init__(self,F,G,index_bytes):
		if not isinstance(F,Point):
			raise TypeError
		if not isinstance(G,Point):
			raise TypeError
		if not isinstance(index_bytes,int):
			raise TypeError
		if not index_bytes > 0:
			raise ValueError
		
		self.F = F
		self.G = G
		self.index_bytes = index_bytes

class SpendKey:
	def __init__(self,params):
		if not isinstance(params,AddressParameters):
			raise TypeError

		self.params = params
		self.s1 = random_scalar()
		self.s2 = random_scalar()
		self.r = random_scalar()
	
class FullViewKey:
	def __init__(self,spend_key):
		if not isinstance(spend_key,SpendKey):
			raise TypeError
		
		self.params = spend_key.params
		self.s1 = spend_key.s1
		self.s2 = spend_key.s2
		self.D = spend_key.r*self.params.G
		self.P2 = self.s2*self.params.F + self.D
	
class IncomingViewKey:
	def __init__(self,full_view_key):
		if not isinstance(full_view_key,FullViewKey):
			raise TypeError

		self.params = full_view_key.params
		self.s1 = full_view_key.s1
		self.P2 = full_view_key.P2
	
	def get_index(self,d):
		# Decrypt the diversifier
		d_key = hash_to_scalar('Spark d',self.s1)
		i_bytes = util.chacha(d_key,d.to_bytes(self.params.index_bytes,'little'))
		i = int.from_bytes(i_bytes,'little')

		return i

class PublicAddress:
	def __init__(self,incoming_view_key,i):
		if not isinstance(incoming_view_key,IncomingViewKey):
			raise TypeError
		if not isinstance(i,int):
			raise TypeError
		if not i >= 0:
			raise ValueError
		
		self.params = incoming_view_key.params

		# Encrypt the diversifier
		d_key = hash_to_scalar('Spark d',incoming_view_key.s1)
		d_bytes = util.chacha(d_key,i.to_bytes(self.params.index_bytes,'little'))
		d = int.from_bytes(d_bytes,'little')

		self.Q1 = incoming_view_key.s1*hash_to_point('Spark div',d)
		self.Q2 = hash_to_scalar('Spark Q2',incoming_view_key.s1,i)*self.params.F + incoming_view_key.P2
