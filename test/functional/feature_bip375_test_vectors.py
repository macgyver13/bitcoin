#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the BIP-375 test vectors against decodepsbt.

The vectors cover the whole of BIP-375, so each one carries a "stage" naming the
role that is expected to accept or reject it. Only the "structure" stage is
implemented so far: parsing the silent payment fields. Vectors belonging to a
later stage are decoded but not asserted on, and the ones needing an optional
PSBT_OUT_SCRIPT cannot be represented yet at all.
"""

import json
import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

# Stages whose rejection happens at sign or finalize time, which Core does not implement yet
DEFERRED_INVALID_STAGES = ["ecdh_coverage", "input_eligibility", "output_scripts"]

# PSBT_GLOBAL_SP_ECDH_SHARE / _DLEQ, PSBT_IN_SP_ECDH_SHARE / _DLEQ, PSBT_OUT_SP_V0_INFO / _LABEL
SP_KEY_TYPES = [0x07, 0x08, 0x09, 0x0a, 0x1d, 0x1e]


class BIP375TestVectorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'bip375_psbt.json')
        with open(path, encoding='utf-8') as f:
            vectors = json.load(f)

        node = self.nodes[0]

        self.log.info("Malformed silent payment PSBTs are rejected by decodepsbt")
        rejected = 0
        for vector in vectors['invalid']:
            if vector['stage'] in DEFERRED_INVALID_STAGES:
                # Structurally well formed, so decodepsbt accepts it. Rejecting these
                # needs the signer, which is not implemented yet.
                node.decodepsbt(vector['psbt'])
                continue
            assert_equal(vector['stage'], 'structure')
            assert_raises_rpc_error(-22, vector['error'], node.decodepsbt, vector['psbt'])
            rejected += 1
        assert_equal(rejected, 6)

        self.log.info("Well formed silent payment PSBTs decode and round-trip")
        decoded = 0
        for vector in vectors['valid']:
            if vector['stage'] == 'in_progress' and 'PSBT_OUT_SCRIPT field is not set' in vector['description']:
                # An output with no PSBT_OUT_SCRIPT cannot be represented until
                # BIP-375 makes that field optional.
                assert_raises_rpc_error(-22, "Output script is required in PSBTv2", node.decodepsbt, vector['psbt'])
                continue
            decode = node.decodepsbt(vector['psbt'])
            # Re-serializing must not drop or alter anything. Core writes the maps in its
            # own canonical order, so compare the decoded form rather than the base64.
            assert_equal(node.decodepsbt(node.combinepsbt([vector['psbt']])), decode)
            self.assert_sp_fields_recognized(decode)
            decoded += 1
        assert_equal(decoded, 16)

    def assert_sp_fields_recognized(self, decode):
        """No BIP-375 field may end up in an "unknown" map, and every vector has at least one."""
        maps = [decode] + decode['inputs'] + decode['outputs']
        for m in maps:
            for key in m.get('unknown', {}):
                assert int(key[:2], 16) not in SP_KEY_TYPES, f"unrecognized BIP-375 field {key}"
        assert any(
            'sp_ecdh_shares' in m or 'sp_dleq_proofs' in m or 'sp_v0_info' in m
            for m in maps
        )


if __name__ == '__main__':
    BIP375TestVectorsTest(__file__).main()
