import socket
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

        print("Device attested!\n")

    def join(self, signature, timestamp):
        byted_operation = (8).to_bytes(4, byteorder='big')
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

        self.client_socket.send(len(byted_msg2).to_bytes(4, byteorder='big'))
        self.client_socket.send(byted_msg2)
        print("msg2 sent!")
        msg3_size_raw = self.client_socket.recv(4)
        msg3_size = int.from_bytes(msg3_size_raw, "big")
        msg3_raw = self.client_socket.recv(msg3_size)
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
        self.client_socket.send(len(byted_msg0).to_bytes(4, byteorder='big'))
        self.client_socket.send(byted_msg0)
        print("msg0 sent!")
        msg1_size_raw = self.client_socket.recv(4)
        msg1_size = int.from_bytes(msg1_size_raw, "big")
        #print("msg1 size:", msg1_size)
        msg1_raw = self.client_socket.recv(msg1_size)
        print("Received msg1!")
        pubKey_len = int.from_bytes(msg1_raw[0:4], "big")
        pubKey = msg1_raw[4:4+pubKey_len]
        ts1_len = int.from_bytes(msg1_raw[4+pubKey_len:8+pubKey_len], "big")
        ts1 = msg1_raw[8+pubKey_len:8+pubKey_len+ts1_len]
        #print("msg1 parsed!")
        return ts1

    def attest_mqtt(self):
        server_host = "localhost"
        server_port = 3602
        self.server_socket.bind((server_host, server_port))
        self.server_socket.listen()
        connection, host = self.server_socket.accept()
        while True:
            msg0_size_raw = connection.recv(4)
            msg0_size = int.from_bytes(msg0_size_raw, "big")
            msg0_raw = connection.recv(msg0_size)
            print("mqtt_msg0 received!")

            self.client_socket.send(msg0_size_raw)
            self.client_socket.send(msg0_raw)

            msg1_size_raw = self.client_socket.recv(4)
            msg1_size = int.from_bytes(msg1_size_raw, "big")
            msg1_raw = self.client_socket.recv(msg1_size)

            connection.send(msg1_size_raw)
            connection.send(msg1_raw)
            nonce = "This is my nonce\0"
            byted_nonce = bytes(nonce, 'ascii')
            byted_nonce_len = len(byted_nonce).to_bytes(4, byteorder='big')
            connection.send(byted_nonce_len)
            connection.send(byted_nonce)

            msg2_size_raw = connection.recv(4)
            msg2_size = int.from_bytes(msg2_size_raw, "big")
            msg2_raw = connection.recv(msg2_size)

            self.client_socket.send(msg2_size_raw)
            self.client_socket.send(msg2_raw)

            msg3_size_raw = self.client_socket.recv(4)
            msg3_size = int.from_bytes(msg3_size_raw, "big")
            msg3_raw = self.client_socket.recv(msg3_size)

            connection.send(msg3_size_raw)
            connection.send(msg3_raw)

            break

    def __init__(self, device_id, app_id, version, claim):
        self.privateKey = 4049546346519992604730332816858472394381393488413156548605745581385
        self.publicKey = schnorr.pubkey_gen(self.privateKey.to_bytes(32, byteorder='big'))
        self.id = device_id
        self.appId = app_id
        self.version = version
        self.attestation_time = None
        self.claim = claim
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_host = "localhost" #"dustberry.panda-ling.ts.net"
        client_port = 2501
        self.client_socket.connect((client_host, client_port))

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

if __name__ == '__main__':
    device_stub = DeviceStub("vedliot2", "app1", "1.0", bytes("measure1", 'ascii'))
    device_stub.attest()
    device_stub.attest_mqtt()
