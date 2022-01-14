import asset_chaum
from dumb25519 import random_point, random_scalar, ScalarVector, PointVector
import unittest

class TestAssetChaum(unittest.TestCase):
	def test_complete(self):
		params = asset_chaum.ChaumParameters(random_point(),random_point(),random_point())
		n = 3

		x = ScalarVector([random_scalar() for _ in range(n)])
		y = ScalarVector([random_scalar() for _ in range(n)])
		z = random_scalar()
		witness = asset_chaum.ChaumWitness(x,y,z)

		C = PointVector([x[i]*params.F + y[i]*params.G + z*params.H for i in range(n)])
		statement = asset_chaum.ChaumStatement(params,C)

		proof = asset_chaum.prove(statement,witness)
		asset_chaum.verify(statement,proof)

if __name__ == '__main__':
	unittest.main()
