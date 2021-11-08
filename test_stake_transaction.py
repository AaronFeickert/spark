import address
import coin
from dumb25519 import random_point
from random import randrange
import stake_transaction
import unittest

def random_public_address():
	return address.PublicAddress(random_point(),random_point(),random_point())

class TestStake(unittest.TestCase):
	def test_stake(self):
		n = 2
		m = 2
		value_bytes = 4
		memo_bytes = 16
		input_value = 3
		stake = 2
		fee = input_value - stake
		delegation_id = 1

		self.assertGreater(n,1)
		self.assertGreater(m,1)

		protocol_params = stake_transaction.ProtocolParameters(random_point(),random_point(),random_point(),random_point(),value_bytes,n,m,stake)
		address_params = address.AddressParameters(protocol_params.F,protocol_params.G)
		coin_params = coin.CoinParameters(protocol_params.F,protocol_params.G,protocol_params.H,protocol_params.U,protocol_params.value_bytes,memo_bytes)

		# Addresses
		spend = address.SpendKey(address_params)
		full = spend.full_view_key()
		incoming = spend.incoming_view_key()
		public = spend.public_address(0)

		# Generate the input set and real coins
		inputs = []
		for _ in range(protocol_params.n**protocol_params.m):
			inputs.append(coin.Coin(coin_params,random_public_address(),randrange(0,2**(8*coin_params.value_bytes)),'Input memo',False,False))
		l = randrange(0,len(inputs))
		inputs[l] = coin.Coin(
			coin_params,
			public,
			input_value,
			'Spend memo',
			False,
			False
		)
		inputs[l].identify(coin_params,incoming)
		inputs[l].recover(coin_params,full)
		inputs[l].delegate(coin_params,full,delegation_id)

		# Generate the spend transaction
		transaction = stake_transaction.StakeTransaction(
			protocol_params,
			full,
			spend,
			inputs,
			l,
			fee
		)

		# Verify it
		transaction.verify(
			protocol_params
		)

if __name__ == '__main__':
	unittest.main()
