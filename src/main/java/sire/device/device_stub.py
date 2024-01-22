import socket
import schnorr

class DeviceStub:
    def attest_mqtt(self, mqtt_id, mqtt_appId, mqtt_version, mqtt_claim):
        mqtt_stub = DeviceStub(mqtt_id, self.appId, self.version, mqtt_claim)

        print("MQTT attested!")
    def attest(self):
        ts1 = self.get_timestamp()

        signing_hash = schnorr.hash_sha256(self.publicKey + bytes(self.version, 'ascii') +
                                           self.claim + bytes(self.appId, 'ascii'))  # + ts1.serializeToString()

        random_priv_key = schnorr.get_random_number().to_bytes(32, byteorder='big')
        random_pub_key = schnorr.pubkey_gen(random_priv_key)
        signature = schnorr.schnorr_sign(signing_hash, random_priv_key, random_pub_key)


        self.attestation_time = self.join(signature, ts1)

        print("Attested!\n")

    def join(self, signature, timestamp):
        byted_operation = (7).to_bytes(4, byteorder='big')
        byted_id = bytes(self.id, 'ascii')
        id_len = len(byted_id).to_bytes(4, byteorder='big')
        byted_appId = bytes(self.appId, 'ascii')
        appId_len = len(byted_appId).to_bytes(4, byteorder='big')
        pubKey_len = len(self.publicKey).to_bytes(4, byteorder='big')


        byted_version = bytes(self.version, 'ascii')
        version_len = len(byted_version).to_bytes(4, byteorder='big')
        claim_len = len(self.claim).to_bytes(4, byteorder='big')
        servicePubKey_len = len(self.publicKey).to_bytes(4, byteorder='big')
        timestamp_len = len(timestamp).to_bytes(4, byteorder='big')
        signature_len = len(signature).to_bytes(4, byteorder='big')

        byted_msg2 = byted_operation + id_len + byted_id + appId_len + byted_appId + pubKey_len + self.publicKey + version_len + byted_version + claim_len + self.claim + timestamp_len + timestamp + signature_len + signature

        self.socket.send(len(byted_msg2).to_bytes(4, byteorder='big'))
        self.socket.send(byted_msg2)
        print("msg2 sent!")
        msg3_size_raw = self.socket.recv(4)
        msg3_size = int.from_bytes(msg3_size_raw, "big")
        msg3_raw = self.socket.recv(msg3_size)
        print("Received msg3!")
        pubKey_len = int.from_bytes(msg3_raw[0:4], "big")
        pubKey = msg3_raw[4:4+pubKey_len]
        ts_len = int.from_bytes(msg3_raw[4+pubKey_len:8+pubKey_len], "big")
        ts = msg3_raw[8+pubKey_len:8+pubKey_len+ts_len]
        hash_len = int.from_bytes(msg3_raw[8+pubKey_len+ts_len:12+pubKey_len+ts_len], "big")
        hash3 = msg3_raw[12+pubKey_len+ts_len:12+pubKey_len+ts_len+hash_len]
        msg3_hash = schnorr.hash_sha256(msg3_raw)
        isSignatureValid = schnorr.schnorr_verify(msg3_raw, pubKey, msg3_hash)
        isHashValid = True#msg3_hash == hash3
        if isSignatureValid & isHashValid:
            return ts
        else:
            return None
        return ts

    def get_timestamp(self):
        byted_id = bytes(self.id, 'ascii')
        id_len = len(byted_id).to_bytes(4, byteorder='big')
        byted_appId = bytes(self.appId, 'ascii')
        appId_len = len(byted_appId).to_bytes(4, byteorder='big')
        pubKey_len = len(self.publicKey).to_bytes(4, byteorder='big')
        byted_operation = (1).to_bytes(4, byteorder='big')

        byted_msg0 = byted_operation + id_len + byted_id + appId_len + byted_appId + pubKey_len + self.publicKey
        self.socket.send(len(byted_msg0).to_bytes(4, byteorder='big'))
        self.socket.send(byted_msg0)
        print("msg0 sent!")
        msg1_size_raw = self.socket.recv(4)
        msg1_size = int.from_bytes(msg1_size_raw, "big")
        #print("msg1 size:", msg1_size)
        msg1_raw = self.socket.recv(msg1_size)
        print("Received msg1!")
        pubKey_len = int.from_bytes(msg1_raw[0:4], "big")
        pubKey = msg1_raw[4:4+pubKey_len]
        ts1_len = int.from_bytes(msg1_raw[4+pubKey_len:8+pubKey_len], "big")
        ts1 = msg1_raw[8+pubKey_len:8+pubKey_len+ts1_len]
        #print("msg1 parsed!")
        return ts1

    def __init__(self, device_id, app_id, version, claim):
        self.privateKey = 4049546346519992604730332816858472394381393488413156548605745581385
        self.publicKey = schnorr.pubkey_gen(self.privateKey.to_bytes(32, byteorder='big'))
        self.id = device_id
        self.appId = app_id
        self.version = version
        self.attestation_time = None
        self.claim = claim
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = "localhost" #"dustberry.panda-ling.ts.net"
        port = 2501
        self.socket.connect((host, port))
        self.attest()


if __name__ == '__main__':
    stub = DeviceStub("vedliot2", "app1", "1.0", bytes("measure1", 'ascii'))
    stub.attest_mqtt("mqtt1", "app1", "1.0", bytes("measure2", 'ascii'))
