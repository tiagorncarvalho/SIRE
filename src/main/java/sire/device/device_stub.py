import socket
import messages_pb2
import schnorr


class DeviceStub:
    def attest(self):
        ts1 = self.get_timestamp()

        signing_hash = schnorr.hash_sha256(self.publicKey + bytes(self.version, 'ascii') +
                                           self.claim + bytes(self.appId, 'ascii'))  # + ts1.serializeToString()

        random_priv_key = schnorr.get_random_number().to_bytes(32, byteorder='big')
        random_pub_key = schnorr.pubkey_gen(random_priv_key)
        signature = schnorr.schnorr_sign(signing_hash, random_priv_key, random_pub_key)


        self.attestation_time = self.join(signature, ts1)

        print("Attested!")

    def join(self, signature, timestamp):
        msg2 = messages_pb2.ProxyMessage()
        msg2.appId = self.appId
        msg2.operation = messages_pb2.ProxyMessage.MEMBERSHIP_JOIN
        msg2.deviceId = self.id
        msg2.evidence.version = self.version
        msg2.evidence.claim = self.claim
        msg2.evidence.servicePubKey = self.publicKey
        msg2.timestamp = timestamp
        msg2.pubKey = self.publicKey
        msg2.signature.sigma = signature
        byted_msg2 = msg2.SerializeToString()
        self.socket.send(len(byted_msg2).to_bytes(4, byteorder='big'))
        self.socket.send(byted_msg2)
        msg3_size_raw = self.socket.recv(4)
        msg3_size = int.from_bytes(msg3_size_raw, "big")
        #print("msg3 size:", msg3_size)
        msg3_raw = self.socket.recv(msg3_size)
        msg3 = messages_pb2.ProxyResponse()
        msg3.ParseFromString(msg3_raw)
        msg3_hash = schnorr.hash_sha256(msg3_raw)
        isSignatureValid = schnorr.schnorr_verify(msg3_raw, msg3.pubKey, msg3_hash)
        isHashValid = True#msg3_hash == msg3.hash
        if isSignatureValid & isHashValid:
            return msg3.timestamp
        else:
            return None
        return timestamp

    def get_timestamp(self):
        msg0 = messages_pb2.ProxyMessage()
        msg0.deviceId = self.id
        msg0.appId = self.appId
        msg0.pubKey = self.publicKey
        msg0.operation = messages_pb2.ProxyMessage.ATTEST_TIMESTAMP
        byted_msg0 = msg0.SerializeToString()
        self.socket.send(len(byted_msg0).to_bytes(4, byteorder='big'))
        self.socket.send(byted_msg0)
        #print("msg0 sent!")
        msg1_size_raw = self.socket.recv(4)
        msg1_size = int.from_bytes(msg1_size_raw, "big")
        #print("msg1 size:", msg1_size)
        msg1_raw = self.socket.recv(msg1_size)
        #print("Received msg1!")
        msg1 = messages_pb2.ProxyResponse()
        msg1.ParseFromString(msg1_raw)
        #print("msg1 parsed!")
        ts1 = msg1.timestamp
        return ts1

    def __init__(self, app_id, version, claim):
        self.privateKey = 4049546346519992604730332816858472394381393488413156548605745581385
        self.publicKey = schnorr.pubkey_gen(self.privateKey.to_bytes(32, byteorder='big'))
        self.id = str(schnorr.hash_sha256(self.publicKey))
        self.appId = app_id
        self.version = version
        self.attestation_time = None
        self.claim = claim
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = "localhost"
        port = 2501
        self.socket.connect((host, port))
        self.attest()


if __name__ == '__main__':
    stub = DeviceStub("app1", "1.0", bytes("measure1", 'ascii'))
