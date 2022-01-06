import address
from dumb25519 import hash_to_point, hash_to_scalar, random_point
from random import randrange
import unittest

class TestAddress(unittest.TestCase):
	def test_generate(self):
		index_bytes = 8
		params = address.AddressParameters(random_point(),random_point(),index_bytes)

		spend = address.SpendKey(params)
		full = spend.full_view_key()
		incoming = spend.incoming_view_key()
		public = spend.public_address(randrange(0,2**(8*index_bytes)))

		self.assertEqual(incoming.s1,spend.s1)
		self.assertEqual(full.s1,spend.s1)
		self.assertEqual(full.s2,spend.s2)
		self.assertEqual(full.D,spend.r*params.G)
		self.assertEqual(public.Q1,spend.s1*hash_to_point())
		self.assertEqual(public.Q2,(hash_to_scalar('Q2',spend.s1,lookahead) + spend.s2)*params.F + spend.r*params.G)

		for i in range(lookahead+2):
			entry = (hash_to_scalar('Q2',spend.s1,i) + spend.s2)*params.F + spend.r*params.G
			if i > lookahead:
				with self.assertRaises(IndexError):
					incoming.get_diversifier(entry)
			else:
				self.assertEqual(incoming.get_diversifier(entry),i)

if __name__ == '__main__':
	unittest.main()
