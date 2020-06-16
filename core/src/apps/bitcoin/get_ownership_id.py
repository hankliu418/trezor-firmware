from trezor import wire
from trezor.messages.GetOwnershipId import GetOwnershipId
from trezor.messages.OwnershipId import OwnershipId

from apps.common import coininfo

from . import addresses, common, scripts
from .keychain import with_keychain
from .ownership import get_identifier

if False:
    from apps.common.seed import Keychain


@with_keychain
async def get_ownership_id(
    ctx, msg: GetOwnershipId, keychain: Keychain, coin: coininfo.CoinInfo
):
    if msg.script_type not in common.INTERNAL_INPUT_SCRIPT_TYPES:
        raise wire.DataError("Invalid script type")

    if msg.script_type in common.SEGWIT_INPUT_SCRIPT_TYPES and not coin.segwit:
        raise wire.DataError("Segwit not enabled on this coin")

    node = keychain.derive(msg.address_n)
    address = addresses.get_address(msg.script_type, coin, node, msg.multisig)
    script_pubkey = scripts.output_derive_script(address, coin)
    ownership_id = get_identifier(script_pubkey, keychain)

    return OwnershipId(ownership_id)
