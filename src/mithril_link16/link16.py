"""SISO-STD-002-2021 low-fidelity DIS 7 transport. No RF or J-series semantics.

Signal fixed-format messages (MTI 0) retain 75-bit words, including parity.
The simulation network header is big endian; subsequent fields are LSB-first
bit streams. Legacy byte-swapped SISO-STD-002-2006 payloads are refused.
"""
from dataclasses import dataclass, asdict
import socket
import struct
from . import Refusal

PDU_HEADER = struct.Struct("!BBBBIHBB")
SIGNAL = struct.Struct("!HHHHHHIHH")
NETWORK = struct.Struct("!HBBBBBBIII")

def uint(value, bits, label):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise Refusal(f"{label} must be an unsigned {bits}-bit integer")
    return value

@dataclass(frozen=True)
class Radio:
    site: int = 1
    application: int = 1
    entity: int = 1
    radio: int = 1

    def values(self):
        return [uint(v, 16, k) for k, v in asdict(self).items()]

@dataclass(frozen=True)
class Network:
    npg: int = 0
    net: int = 0
    tsec: int = 255
    msec: int = 255
    message_type: int = 0
    siso_version: int = 1
    link16_version: int = 0
    time_slot: int = 0xffffffff
    ntp_seconds: int = 0xffffffff
    ntp_fraction: int = 0xffffffff

    def encode(self):
        uint(self.npg, 9, "NPG")
        uint(self.net, 7, "net")
        uint(self.link16_version, 8, "Link 16 version")
        if (self.tsec, self.msec, self.time_slot, self.ntp_seconds, self.ntp_fraction) != (
                255, 255, 0xffffffff, 0xffffffff, 0xffffffff):
            raise Refusal("v1 transport supports TSA level 0 wildcard timing and crypto only")
        if self.siso_version != 1 or self.message_type != 0:
            raise Refusal("only SISO 2021 fixed-format message type 0 is supported")
        return NETWORK.pack(*asdict(self).values())

def header(pdu_type, length, exercise, timestamp):
    return PDU_HEADER.pack(7, uint(exercise, 8, "exercise"), pdu_type, 4,
                           uint(timestamp, 32, "DIS timestamp"), uint(length, 16, "length"), 0, 0)

def check_header(data, pdu_type):
    if not isinstance(data, bytes) or len(data) < 12:
        raise Refusal("truncated DIS header")
    version, exercise, typ, family, timestamp, length, status, pad = PDU_HEADER.unpack_from(data)
    if (version, typ, family) != (7, pdu_type, 4):
        raise Refusal("unexpected DIS version, PDU type or protocol family")
    if length != len(data) or length % 4 or status or pad:
        raise Refusal("invalid DIS length/status/padding")
    return {"exercise": exercise, "timestamp": timestamp}

def encode_signal(words, radio=Radio(), network=Network(), *, jtids_header=0,
                  exercise=1, timestamp=0):
    if not isinstance(words, (list, tuple)) or not 1 <= len(words) <= 816:
        raise Refusal("fixed-format signal requires 1 through 816 J words")
    uint(jtids_header, 35, "JTIDS header (padding excluded)")
    bit_stream = jtids_header.to_bytes(6, "little") + b"".join(
        uint(word, 75, "opaque J word").to_bytes(10, "little") for word in words)
    payload = network.encode() + bit_stream
    bit_length = len(payload) * 8
    padding = bytes((-len(payload)) % 4)
    body = SIGNAL.pack(*radio.values(), 0x4000 | len(words), 100, 0, bit_length, 0)
    return header(26, 32 + len(payload) + len(padding), exercise, timestamp) + body + payload + padding

def decode_signal(data):
    result = check_header(data, 26)
    if len(data) < 68:
        raise Refusal("truncated fixed-format Signal PDU")
    site, app, entity, radio_id, encoding, tdl, rate, bits, samples = SIGNAL.unpack_from(data, 12)
    count = encoding & 0x3fff
    if encoding >> 14 != 1 or tdl != 100 or rate or samples or not 1 <= count <= 816:
        raise Refusal("Signal PDU is outside the fixed-format Link 16 profile")
    expected = 208 + 80 * count
    if bits != expected or len(data) != 32 + ((bits + 31) // 32) * 4:
        raise Refusal("Signal PDU word count/data length mismatch")
    network = Network(*NETWORK.unpack_from(data, 32))
    network.encode()  # Validate enums and declared TSA profile.
    start = 52
    jtids = int.from_bytes(data[start:start + 6], "little")
    if jtids >> 35:
        raise Refusal("nonzero JTIDS header padding")
    words = [int.from_bytes(data[start + 6 + 10 * i:start + 16 + 10 * i], "little") for i in range(count)]
    if any(word >> 75 for word in words) or any(data[32 + bits // 8:]):
        raise Refusal("nonzero word/PDU padding")
    return {**result, "radio": asdict(Radio(site, app, entity, radio_id)),
            "network": asdict(network), "jtidsHeader": jtids,
            # Hex avoids losing >53-bit integer precision in Mithril's JS host.
            "wordsHex": [format(word, "019x") for word in words], "wordSemantics": "opaque"}

def encode_transmitter(radio=Radio(), *, exercise=1, timestamp=0, mode=4,
                       transmit_state=2, primary=2, secondary=0, network_id=0):
    if mode not in {1, 2, 4} or transmit_state not in {0, 1, 2} or primary not in {1, 2} or secondary not in {0, 1, 2, 3}:
        raise Refusal("invalid low-fidelity transmitter mode/state")
    uint(network_id, 32, "network synchronization ID")
    body = struct.pack("!4H", *radio.values())
    body += struct.pack("!BBHBBBB", 7, 0, 0, 21, 0, 0, 0)  # DIS radio entity kind, Link 16 category
    body += struct.pack("!BBH", transmit_state, 8, 0)  # no variable transmitter records
    body += struct.pack("!3d3fHH", 0, 0, 0, 0, 0, 0, 0, 0)  # no antenna pattern
    body += struct.pack("!Qff", 1131000000 if mode == 1 else 969000000,
                        240000000 if mode == 1 else 3000000, 0)
    body += struct.pack("!6HBBH", int(mode == 1), 7, 0, 8, 0, 0, 8, 0, 0)
    body += struct.pack("!BBBBI", 0, primary, secondary, 3, network_id)
    if len(body) != 100:
        raise AssertionError("Transmitter layout size mismatch")
    return header(25, 112, exercise, timestamp) + body

def decode_transmitter(data):
    result = check_header(data, 25)
    if len(data) != 112:
        raise Refusal("only fixed Transmitter PDU without antenna/variable records is supported")
    radio = Radio(*struct.unpack_from("!4H", data, 12))
    kind, domain, country, category, subcategory, specific, extra = struct.unpack_from("!BBHBBBB", data, 20)
    state, source, records = struct.unpack_from("!BBH", data, 28)
    antenna_type, antenna_length = struct.unpack_from("!HH", data, 68)
    freq, bandwidth, power = struct.unpack_from("!Qff", data, 72)
    spread, major, detail, system, crypto, key, mlen, pad1, pad2 = struct.unpack_from("!6HBBH", data, 88)
    tsa, primary, secondary, sync, network_id = struct.unpack_from("!BBBBI", data, 104)
    if (kind, category, source, records, antenna_type, antenna_length, major, detail, system,
            crypto, key, mlen, pad1, pad2, tsa, sync) != (7, 21, 8, 0, 0, 0, 7, 0, 8, 0, 0, 8, 0, 0, 0, 3):
        raise Refusal("Transmitter PDU is outside the TSA level 0 profile")
    if state not in {0, 1, 2} or primary not in {1, 2} or secondary not in {0, 1, 2, 3}:
        raise Refusal("unsupported transmitter state/mode")
    if (spread, freq, bandwidth) not in {(1, 1131000000, 240000000), (0, 969000000, 3000000)}:
        raise Refusal("inconsistent transmitter frequency/modulation")
    return {**result, "radio": asdict(radio), "tsa": tsa, "primary": primary,
            "secondary": secondary, "sync": sync, "networkId": network_id,
            "transmitState": state, "frequency": freq}

class UDPTransport:
    """Bounded real UDP transport. Caller explicitly supplies numeric bind/peer.
    Default is ephemeral IPv4 loopback; external peers require an exact allowlist.
    No RF terminal control or implicit broadcast/multicast discovery.
    """
    def __init__(self, bind=("127.0.0.1", 0), allowed_peers=(), timeout=2):
        import ipaddress
        ipaddress.IPv4Address(bind[0])
        self.allowed = {tuple(peer) for peer in allowed_peers}
        for ip, port in self.allowed:
            ipaddress.IPv4Address(ip)
            uint(port, 16, "peer port")
        if not 0 < timeout <= 60:
            raise Refusal("UDP timeout must be 0 through 60 seconds")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.settimeout(timeout)
            self.socket.bind(bind)
        except BaseException:
            self.socket.close()
            raise

    @property
    def address(self):
        return self.socket.getsockname()

    def send(self, data, peer):
        if tuple(peer) not in self.allowed:
            raise Refusal("UDP peer is not explicitly allowed")
        self.decode(data)
        return self.socket.sendto(data, peer)

    @staticmethod
    def decode(data):
        if len(data) < 3:
            raise Refusal("truncated DIS datagram")
        if data[2] == 26:
            return decode_signal(data)
        if data[2] == 25:
            return decode_transmitter(data)
        raise Refusal("unsupported DIS PDU type")

    def receive(self):
        data, peer = self.socket.recvfrom(65536)
        if peer not in self.allowed:
            raise Refusal("received UDP peer is not allowed")
        return {"peer": list(peer), "bytesHex": data.hex(), "decoded": self.decode(data)}

    def close(self):
        self.socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
