import address
from dumb25519 import hash_to_point, hash_to_scalar, random_point
from random import randrange
import unittest
import util

class TestAddress(unittest.TestCase):
	def test_generate(self):
		index_bytes = 8
		params = address.AddressParameters(random_point(),random_point(),index_bytes)

		i = randrange(0,2**(8*index_bytes))
		spend_key = address.SpendKey(params)
		full_view_key = address.FullViewKey(spend_key)
		incoming_view_key = address.IncomingViewKey(full_view_key)
		public_address = address.PublicAddress(incoming_view_key,i)

		# Full view key components
		self.assertEqual(full_view_key.s1,spend_key.s1)
		self.assertEqual(full_view_key.s2,spend_key.s2)
		self.assertEqual(full_view_key.D,spend_key.r*params.G)
		self.assertEqual(full_view_key.P2,spend_key.s2*params.F+full_view_key.D)

		# Incoming view key components
		self.assertEqual(incoming_view_key.s1,full_view_key.s1)
		self.assertEqual(incoming_view_key.P2,full_view_key.P2)

		# Address components
		d_key = hash_to_scalar('Spark d',incoming_view_key.s1)
		d_bytes = util.chacha(d_key,i.to_bytes(params.index_bytes,'little'))
		d = int.from_bytes(d_bytes,'little')

		self.assertEqual(public_address.Q1,incoming_view_key.s1*hash_to_point('Spark div',d))
		self.assertEqual(public_address.Q2,hash_to_scalar('Spark Q2',incoming_view_key.s1,i)*params.F + incoming_view_key.P2)

		self.assertEqual(incoming_view_key.get_index(d),i)

if __name__ == '__main__':
	unittest.main()
