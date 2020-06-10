from common import unhexlify, unittest
from trezor.crypto import bip39
from trezor.messages import InputScriptType

from apps.common import coins
from apps.common.seed import Keychain
from apps.common.paths import HARDENED
from apps.bitcoin import ownership, scripts
from apps.bitcoin.addresses import address_p2wpkh, address_p2wpkh_in_p2sh


class TestOwnershipProof(unittest.TestCase):

    def test_p2wpkh_gen_proof(self):
        coin = coins.by_name('Bitcoin')
        seed = bip39.seed(' '.join(['all'] * 12), '')
        keychain = Keychain(seed, [[coin.curve_name, [84 | HARDENED]], ["slip21", [b"SLIP-0019"]]])
        commitment_data = b""

        node = keychain.derive([84 | HARDENED, 0 | HARDENED, 0 | HARDENED, 1, 0])
        address = address_p2wpkh(node.public_key(), coin)
        script_pubkey = scripts.output_derive_script(address, coin)
        ownership_id = ownership.get_identifier(script_pubkey, keychain)
        self.assertEqual(ownership_id, unhexlify("a122407efc198211c81af4450f40b235d54775efd934d16b9e31c6ce9bad5707"))

        proof = ownership.generate_proof(
            node=node,
            script_type=InputScriptType.SPENDWITNESS,
            multisig=None,
            coin=coin,
            user_confirmed=False,
            ownership_ids=[ownership_id],
            script_pubkey=script_pubkey,
            commitment_data=b"",
        )

        self.assertEqual(proof, unhexlify("534c00190001a122407efc198211c81af4450f40b235d54775efd934d16b9e31c6ce9bad57070002483045022100e5eaf2cb0a473b4545115c7b85323809e75cb106175ace38129fd62323d73df30220363dbc7acb7afcda022b1f8d97acb8f47c42043cfe0595583aa26e30bc8b3bb50121032ef68318c8f6aaa0adec0199c69901f0db7d3485eb38d9ad235221dc3d61154b"))

        self.assertFalse(ownership.verify_nonownership(proof, script_pubkey, commitment_data, keychain, coin))

    def test_p2wpkh_in_p2sh_gen_proof(self):
        coin = coins.by_name('Bitcoin')
        seed = bip39.seed(' '.join(['all'] * 12), '')
        keychain = Keychain(seed, [[coin.curve_name, [49 | HARDENED]], ["slip21", [b"SLIP-0019"]]])
        commitment_data = b""

        node = keychain.derive([49 | HARDENED, 0 | HARDENED, 0 | HARDENED, 1, 0])
        address = address_p2wpkh_in_p2sh(node.public_key(), coin)
        script_pubkey = scripts.output_derive_script(address, coin)
        ownership_id = ownership.get_identifier(script_pubkey, keychain)

        self.assertEqual(ownership_id, unhexlify("92caf0b8daf78f1d388dbbceaec34bd2dabc31b217e32343663667f6694a3f46"))

        proof = ownership.generate_proof(
            node=node,
            script_type=InputScriptType.SPENDP2SHWITNESS,
            multisig=None,
            coin=coin,
            user_confirmed=False,
            ownership_ids=[ownership_id],
            script_pubkey=script_pubkey,
            commitment_data=b"",
        )

        self.assertEqual(proof, unhexlify("534c0019000192caf0b8daf78f1d388dbbceaec34bd2dabc31b217e32343663667f6694a3f4617160014e0cffbee1925a411844f44c3b8d81365ab51d03602483045022100a37330dca699725db613dd1b30059843d1248340642162a0adef114509c9849402201126c9044b998065d40b44fd2399b52c409794bbc3bfdd358cd5fb450c94316d012103a961687895a78da9aef98eed8e1f2a3e91cfb69d2f3cf11cbd0bb1773d951928"))

        self.assertFalse(ownership.verify_nonownership(proof, script_pubkey, commitment_data, keychain, coin))

    def test_p2pkh_gen_proof(self):
        coin = coins.by_name('Bitcoin')
        seed = bip39.seed(' '.join(['all'] * 12), 'TREZOR')
        keychain = Keychain(seed, [[coin.curve_name, [44 | HARDENED]], ["slip21", [b"SLIP-0019"]]])
        commitment_data = b""

        node = keychain.derive([44 | HARDENED, 0 | HARDENED, 0 | HARDENED, 1, 0])
        address = node.address(coin.address_type)
        script_pubkey = scripts.output_derive_script(address, coin)
        ownership_id = ownership.get_identifier(script_pubkey, keychain)
        self.assertEqual(ownership_id, unhexlify("ccc49ac5fede0efc80725fbda8b763d4e62a221c51cc5425076cffa7722c0bda"))

        proof = ownership.generate_proof(
            node=node,
            script_type=InputScriptType.SPENDADDRESS,
            multisig=None,
            coin=coin,
            user_confirmed=False,
            ownership_ids=[ownership_id],
            script_pubkey=script_pubkey,
            commitment_data=b"",
        )

        self.assertEqual(proof, unhexlify("534c00190001ccc49ac5fede0efc80725fbda8b763d4e62a221c51cc5425076cffa7722c0bda6a47304402206682f40a12f3609a308acb872888470a07760f2f4790ee4ff62665a39c02a5fc022026f3f38a7c2b2668c2eff9cc1e712c7f254926a482bae411ad18947eba9fd21c012102f63159e21fbcb54221ec993def967ad2183a9c243c8bff6e7d60f4d5ed3b386500"))

        self.assertFalse(ownership.verify_nonownership(proof, script_pubkey, commitment_data, keychain, coin))

    def test_p2wpkh_verify_proof(self):
        coin = coins.by_name('Bitcoin')
        seed = bip39.seed(' '.join(['all'] * 12), 'TREZOR')
        keychain = Keychain(seed, [["slip21", [b"SLIP-0019"]]])
        commitment_data = b""

        # Proof for "all all ... all" seed without passphrase.
        script_pubkey = unhexlify("0014b2f771c370ccf219cd3059cda92bdf7f00cf2103")
        proof = unhexlify("534c00190001a122407efc198211c81af4450f40b235d54775efd934d16b9e31c6ce9bad57070002483045022100e5eaf2cb0a473b4545115c7b85323809e75cb106175ace38129fd62323d73df30220363dbc7acb7afcda022b1f8d97acb8f47c42043cfe0595583aa26e30bc8b3bb50121032ef68318c8f6aaa0adec0199c69901f0db7d3485eb38d9ad235221dc3d61154b")
        self.assertTrue(ownership.verify_nonownership(proof, script_pubkey, commitment_data, keychain, coin))


if __name__ == '__main__':
    unittest.main()
