import address
from dumb25519 import random_point
from random import randrange
import payout_transaction 
import unittest

class TestPayout(unittest.TestCase):
	def test_payout(self):
		protocol_params = payout_transaction.ProtocolParameters(random_point(),random_point(),random_point(),random_point(),4,32)
		address_params = address.AddressParameters(protocol_params.F,protocol_params.G)

		# Payout data
		public = address.SpendKey(address_params).public_address()
		value = randrange(0,2**(8*protocol_params.value_bytes))

		# Generate the payout transaction
		transaction = payout_transaction.PayoutTransaction(
			protocol_params,
			public,
			value
		)

		# Verify it
		transaction.verify(
			protocol_params
		)

if __name__ == '__main__':
	unittest.main()
