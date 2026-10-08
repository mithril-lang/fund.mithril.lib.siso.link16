from pathlib import Path
import base64
from . import Refusal
from . import link16
ROOT = Path(__file__).resolve().parents[2]
def loopback():
    """Real UDP read-back, including transmitter and fixed-format Signal PDUs."""
    with link16.UDPTransport() as receiver, link16.UDPTransport(allowed_peers=[receiver.address]) as sender:
        receiver.allowed.add(sender.address)
        transmitter = link16.encode_transmitter()
        signal = link16.encode_signal([0x12345, 0x23456], network=link16.Network(npg=7, net=3))
        packets = []
        for packet in [transmitter, signal]:
            sent = sender.send(packet, receiver.address)
            received = receiver.receive()
            if received["bytesHex"] != packet.hex():
                raise Refusal("UDP binary read-back mismatch")
            packets.append({"sentBytes": sent, "received": received["decoded"]})
        return {"transport": "udp-loopback", "binaryReadBack": True,
                "tsaLevel": 0, "rfEffects": False, "packets": packets}

def call(request):
    operation = request.get("operation")
    if operation == "link16-encode":
        words = [int(word, 16) for word in request["wordsHex"]]
        return {"bytesHex": link16.encode_signal(words, link16.Radio(**request.get("radio", {})),
                                                  link16.Network(**request.get("network", {})),
                                                  jtids_header=request.get("jtidsHeader", 0)).hex()}
    if operation == "link16-decode":
        return link16.UDPTransport.decode(bytes.fromhex(request["bytesHex"]))
    if operation == "link16-loopback":
        return loopback()
    if operation == "link16-send":
        peer = tuple(request["peer"])
        with link16.UDPTransport(tuple(request.get("bind", ["127.0.0.1", 0])), request["allowedPeers"]) as transport:
            count = transport.send(bytes.fromhex(request["bytesHex"]), peer)
        return {"sentBytes": count, "peer": list(peer), "deliveryConfirmed": False, "rfEffects": False}
    if operation == "link16-receive":
        with link16.UDPTransport(tuple(request["bind"]), request["allowedPeers"], request.get("timeout", 2)) as transport:
            return transport.receive()
    raise Refusal("unsupported plugin operation")

class Plugin:
    id = "fund.mithril.lib.siso.link16"
    rpc_version = 1
    operations = ('link16-encode', 'link16-decode', 'link16-loopback', 'link16-send', 'link16-receive')
    call = staticmethod(call)
