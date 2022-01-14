import double_bpplus
from dumb25519 import random_point, random_scalar, Scalar, ScalarVector, PointVector
from random import randrange
import unittest

class TestDoubleBPPlus(unittest.TestCase):
	def test_complete(self):
		params = double_bpplus.RangeParameters(random_point(),random_point(),random_point(),4)
		n_commits = 2
		n_proofs = 4

		statements = []
		proofs = []
		for _ in range(n_proofs):
			v = ScalarVector([Scalar(randrange(0,2**params.N)) for _ in range(n_commits)])
			a = ScalarVector([random_scalar() for _ in range(n_commits)])
			r = ScalarVector([random_scalar() for _ in range(n_commits)])
			witness = double_bpplus.RangeWitness(v,a,r)

			C = PointVector([v[i]*params.H + a[i]*params.H_ + r[i]*params.G for i in range(n_commits)])
			statement = double_bpplus.RangeStatement(params,C)
			statements.append(statement)

			proof = double_bpplus.prove(statement,witness)
			proofs.append(proof)

		double_bpplus.verify(statements,proofs)

if __name__ == '__main__':
	unittest.main()