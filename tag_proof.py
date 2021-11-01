# Tag correspondence proof
#
# {(F,G,U),S,T ; (x,y) | S = xF + yG, U = xT + yG}

from dumb25519 import Point, Scalar, hash_to_scalar, random_scalar
import transcript

class TagParameters:
	def __init__(self,F,G,U):
		if not isinstance(F,Point):
			raise TypeError('Bad type for parameter F!')
		if not isinstance(G,Point):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(U,Point):
			raise TypeError('Bad type for parameter U!')
		
		self.F = F
		self.G = G
		self.U = U

class TagStatement:
	def __init__(self,params,context,S,T):
		if not isinstance(params,TagParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(S,Point):
			raise TypeError('Bad type for tag statement input S!')
		if not isinstance(T,Point):
			raise TypeError('Bad type for tag statement input T!')
		
		self.F = params.F
		self.G = params.G
		self.U = params.U
		self.context = context
		self.S = S
		self.T = T

class TagWitness:
	def __init__(self,x,y):
		if not isinstance(x,Scalar):
			raise TypeError('Bad type for tag witness x!')
		if not isinstance(y,Scalar):
			raise TypeError('Bad type for tag witness y!')
		
		self.x = x
		self.y = y

class TagProof:
	def __repr__(self):
		return repr(hash_to_scalar(
			self.A1,
			self.A2,
			self.t1,
			self.t2,
		))

	def __init__(self,A1,A2,t1,t2):
		if not isinstance(A1,Point):
			raise TypeError('Bad type for tag proof element A1!')
		if not isinstance(A2,Point):
			raise TypeError('Bad type for tag proof element A2!')
		if not isinstance(t1,Scalar):
			raise TypeError('Bad type for tag proof element t1!')
		if not isinstance(t2,Scalar):
			raise TypeError('Bad type for tag proof element t2!')

		self.A1 = A1
		self.A2 = A2
		self.t1 = t1
		self.t2 = t2

def challenge(statement,A1,A2):
	if not isinstance(statement,TagStatement):
		raise TypeError('Bad type for tag statement!')
	if not isinstance(A1,Point):
		raise TypeError('Bad type for challenge input A1!')
	if not isinstance(A2,Point):
		raise TypeError('Bad type for challenge input A2!')

	tr = transcript.Transcript('Tag correspondence')
	tr.update(statement.F)
	tr.update(statement.G)
	tr.update(statement.U)
	tr.update(statement.context)
	tr.update(statement.S)
	tr.update(statement.T)
	tr.update(A1)
	tr.update(A2)
	return tr.challenge()

def prove(statement,witness):
	if not isinstance(statement,TagStatement):
		raise TypeError('Bad type for tag statement!')
	if not isinstance(witness,TagWitness):
		raise TypeError('Bad type for tag witness!')
	
	# Check the statement validity
	if not statement.S == witness.x*statement.F + witness.y*statement.G:
		raise ArithmeticError('Invalid tag statement!')
	if not statement.U == witness.x*statement.T + witness.y*statement.G:
		raise ArithmeticError('Invalid tag statement!')
	
	r = random_scalar()
	s = random_scalar()

	A1 = r*statement.F + s*statement.G
	A2 = r*statement.T + s*statement.G

	c = challenge(statement,A1,A2)

	t1 = r + c*witness.x
	t2 = s + c*witness.y

	return TagProof(A1,A2,t1,t2)

def verify(statement,proof):
	if not isinstance(statement,TagStatement):
		raise TypeError('Bad type for tag statement!')
	if not isinstance(proof,TagProof):
		raise TypeError('Bad type for tag proof!')
	
	c = challenge(statement,proof.A1,proof.A2)

	if not proof.A1 + c*statement.S == proof.t1*statement.F + proof.t2*statement.G:
		raise ArithmeticError('Failed tag verification!')
	if not proof.A2 + c*statement.U == proof.t1*statement.T + proof.t2*statement.G:
		raise ArithmeticError('Failed tag verification!')
