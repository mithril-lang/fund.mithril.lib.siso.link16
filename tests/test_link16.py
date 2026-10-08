from io import BytesIO
import struct
import unittest
from mithril_interop import Refusal
from mithril_link16 import link16 as link
from mithril_link16.plugin import loopback

class LinkTests(unittest.TestCase):
    def test_official_layout_golden_vector_and_bit_stream_orientation(self):
        # Independent fixed vector: DIS7 header, signal fields, network header,
        # 35-bit JTIDS header+padding, 75-bit J word+padding. SISO tables 7-9/17.
        expected = bytes.fromhex(
            "07011a040000000000440000"
            "0001000100010001400100640000000001200000"
            "000000ffff000100ffffffffffffffffffffffff"
            "010000000000"
            "45230100000000000000")
        actual = link.encode_signal([0x12345], jtids_header=1)
        self.assertEqual(expected, actual)
        self.assertEqual(["0000000000000012345"], link.decode_signal(expected)["wordsHex"])

    def test_word_boundaries_pdu_padding_and_maximum_75_bit_word(self):
        for count in [1, 2, 3, 816]:
            words = [(1 << 75) - 1] * count
            data = link.encode_signal(words, network=link.Network(npg=511, net=127))
            result = link.decode_signal(data)
            self.assertEqual(count, len(result["wordsHex"]))
            self.assertTrue(all(int(word, 16) == (1 << 75) - 1 for word in result["wordsHex"]))
            self.assertEqual(0, len(data) % 4)
            self.assertEqual(208 + 80 * count, struct.unpack_from("!H", data, 28)[0])
        for words in [[], [1 << 75], [True], [0] * 817]:
            with self.assertRaises(Refusal):
                link.encode_signal(words)

    def test_mutated_length_count_enum_legacy_and_nonzero_padding_refuse(self):
        original = link.encode_signal([123, 456])
        for offset, value in [(0, 6), (2, 25), (9, 1), (23, 3), (38, 0), (67, 0x80), (79, 1)]:
            data = bytearray(original)
            data[offset] = value
            with self.assertRaises(Refusal, msg=str(offset)):
                link.decode_signal(bytes(data))
        with self.assertRaises(Refusal):
            link.encode_signal([1], network=link.Network(siso_version=0))
        with self.assertRaises(Refusal):
            link.encode_signal([1], network=link.Network(message_type=3))

    def test_transmitter_roundtrip_and_unsupported_tsa_refuses(self):
        for mode in [1, 2, 4]:
            data = link.encode_transmitter(mode=mode, network_id=123)
            result = link.decode_transmitter(data)
            self.assertEqual(123, result["networkId"])
            self.assertEqual(0, result["tsa"])
            self.assertEqual(112, len(data))
        data = bytearray(data)
        data[104] = 4
        with self.assertRaises(Refusal):
            link.decode_transmitter(bytes(data))

    def test_real_udp_binary_roundtrip_and_peer_allowlist(self):
        self.assertTrue(loopback()["binaryReadBack"])
        with link.UDPTransport() as transport:
            with self.assertRaises(Refusal):
                transport.send(link.encode_signal([1]), ("127.0.0.1", 9))

    def test_independent_opendis_decoder_reads_signal_and_transmitter(self):
        try:
            from opendis.dis7 import SignalPdu, TransmitterPdu
            from opendis.DataInputStream import DataInputStream
        except ImportError:
            self.skipTest("optional independent validation: pip install opendis==1.0")
        s = SignalPdu()
        s.parse(DataInputStream(BytesIO(link.encode_signal([0x12345]))))
        self.assertEqual((7, 26, 100, 0x4001), (s.protocolVersion, s.pduType, s.tdlType, s.encodingScheme))
        self.assertEqual([0x45, 0x23, 1], s.data[26:29])
        t = TransmitterPdu()
        t.parse(DataInputStream(BytesIO(link.encode_transmitter())))
        self.assertEqual((25, 21, 8, 969000000), (t.pduType, t.radioEntityType.category, t.inputSource, t.frequency))
        self.assertEqual([0, 2, 0, 3, 0, 0, 0, 0], t.modulationParametersList)

if __name__ == "__main__":
    unittest.main()
