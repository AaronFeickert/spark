from dumb25519 import *
from multisig import *
from random import sample
import pytest

@pytest.mark.asyncio
async def test_multisig():
	# Test parameters
	nu = 4
	t = 2

	# Set up the players
	players = {}
	for alpha in range(1,nu+1):
		players[alpha] = Player(alpha,nu,t)
	for alpha in range(1,nu+1):
		players[alpha].set_neighbors(players)

	# Generate keys
	tasks = [asyncio.ensure_future(players[alpha].keygen()) for alpha in range(1,nu+1)]
	await asyncio.wait(tasks)

	# Check keys match
	D = Z
	s1 = Scalar(0)
	s2 = Scalar(0)
	for alpha in range(1,nu+1):
		if alpha > 1:
			assert players[alpha].D == D
			assert players[alpha].s1 == s1
			assert players[alpha].s2 == s2

		D = players[alpha].D
		s1 = players[alpha].s1
		s2 = players[alpha].s2

	# Precompute signing nonce
	tasks = [asyncio.ensure_future(players[alpha].precompute()) for alpha in range(1,nu+1)]
	await asyncio.wait(tasks)

	# Sign message
	m = 'Our first obligation is to keep the foo counters turning'
	x = random_scalar()
	z = random_scalar()
	S = x*F + D + z*H
	T = x.invert()*(U - D)

	statement = SigningStatement(m,S,T)
	witness = SigningWitness(x,z)

	signers = sample(range(1,nu+1),t)
	tasks = [asyncio.ensure_future(players[alpha].sign(signers,statement,witness)) for alpha in signers]
	await asyncio.wait(tasks)

	# Check signature values match across all signers
	A1 = Z
	A2 = Z
	t1 = Scalar(0)
	t2 = Scalar(0)
	t3 = Scalar(0)
	flag = False
	for alpha in signers:
		if flag:
			assert players[alpha].A1 == A1
			assert players[alpha].A2 == A2
			assert players[alpha].t1 == t1
			assert players[alpha].t2 == t2
			assert players[alpha].t3 == t3
		
		flag = True
		
		A1 = players[alpha].A1
		A2 = players[alpha].A2
		t1 = players[alpha].t1
		t2 = players[alpha].t2
		t3 = players[alpha].t3
	
	# Pop the nonces
	for alpha in range(1,nu+1):
		for beta in signers:
			players[alpha].L[beta].pop()
	for beta in signers:
		players[beta].l.pop()
	
	# Verify the signature
	c = challenge(statement,A1,A2)
	assert A1 + c*S == t1*F + t2*G + t3*H
	assert A2 + c*U == t1*T + t2*G
