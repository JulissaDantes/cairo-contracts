import pytest
import asyncio
from starkware.starknet.testing.starknet import Starknet
from utils import (
    assert_revert, to_uint
)

INITIAL_COUNTER = 0

@pytest.fixture(scope='module')
def event_loop():
    return asyncio.new_event_loop()

@pytest.fixture(scope='module')
async def reentrancy_mock():
    starknet = await Starknet.empty()
    contract = await starknet.deploy("tests/mocks/reentrancy_mock.cairo", constructor_calldata=[INITIAL_COUNTER])

    return contract, starknet

@pytest.mark.asyncio
async def test_reentrancy_guard_deploy(reentrancy_mock):
    contract, starknet = reentrancy_mock
    response = await contract.current_count().call()

    assert response.result == (INITIAL_COUNTER,)

@pytest.mark.asyncio
async def test_reentrancy_guard_remote_callback(reentrancy_mock):
    contract, starknet = reentrancy_mock
    attacker = await starknet.deploy("tests/mocks/reentrancy_attacker_mock.cairo")
    # should not allow remote callback
    await assert_revert(
        contract.count_and_call(attacker.contract_address).invoke(),
        reverted_with="ReentrancyGuard: reentrant call"
    )

@pytest.mark.asyncio
async def test_reentrancy_guard_local_recursion(reentrancy_mock):
    contract, starknet = reentrancy_mock
    # should not allow local recursion
    await assert_revert(
        contract.count_local_recursive(10).invoke(),
        reverted_with="ReentrancyGuard: reentrant call"
    )
    # should not allow indirect local recursion
    await assert_revert(
        contract.count_this_recursive(to_uint(10), to_uint(1)).invoke(),
        reverted_with="ReentrancyGuard: reentrant call"
    )