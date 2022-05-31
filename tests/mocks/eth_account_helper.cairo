%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from starkware.cairo.common.cairo_secp.bigint import BigInt3
from starkware.cairo.common.cairo_secp.signature import public_key_point_to_eth_address
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.syscalls import get_tx_signature

#
# Storage Variables
#
@storage_var
func public_key() -> (res: felt):
end

#
# Constructor
#

@constructor
func constructor{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr: BitwiseBuiltin*
    }(x: BigInt3, y: BigInt3):
    alloc_locals
    let (local keccak_ptr : felt*) = alloc()
    let key_point = EcPoint(x=x,y=y)
    with keccak_ptr:
        let (_public_key: felt) = public_key_point_to_eth_address(key_point)
    end
    public_key.write(_public_key)
    return ()
end

#
# Getters
#

@view
func get_public_key{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = public_key.read()
    return (res=res)
end
