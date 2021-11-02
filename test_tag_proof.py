import tag_proof
from dumb25519 import random_point, random_scalar
import unittest

class TestTagProof(unittest.TestCase):
	def test_complete(self):
		params = tag_proof.TagParameters(random_point(),random_point(),random_point())

		x = random_scalar()
		y = random_scalar()
		witness = tag_proof.TagWitness(x,y)

		S = x*params.F + y*params.G
		T = x.invert()*(params.U - y*params.G)
		statement = tag_proof.TagStatement(params,'Proof context',S,T)

		proof = tag_proof.prove(statement,witness)
		tag_proof.verify(statement,proof)

if __name__ == '__main__':
	unittest.main()
