import socket
import schnorr
import hashlib

class MQTTStub:

    def mqtt_attest(self):
        ts1 = self.get_timestamp()
        attestation_time = self.join(ts1)
        if attestation_time is None:
            print("MQTT attestation failed!")
        else:
            print("MQTT attested!\n")

    def compute_claim(self):
        m = hashlib.sha256()
        m.update(self.claim)
        claim_hash = m.digest()

        m2 = hashlib.sha256()
        m2.update(claim_hash)
        m2.update(self.nonce)
        return m2.digest()

    def join(self, timestamp):
        byted_operation = (9).to_bytes(4, byteorder='big')
        byted_id = bytes(self.id, 'ascii')
        id_len = len(byted_id).to_bytes(4, byteorder='big')
        byted_appId = bytes(self.appId, 'ascii')
        appId_len = len(byted_appId).to_bytes(4, byteorder='big')
        byted_evidence = bytes(self.evidence, 'ascii')
        evidence_len = len(byted_evidence).to_bytes(4, byteorder='big')
        nonce_len = len(self.nonce).to_bytes(4, byteorder='big')
        timestamp_len = len(timestamp).to_bytes(4, byteorder='big')

        byted_msg2 = byted_operation + id_len + byted_id + appId_len + byted_appId + evidence_len + byted_evidence + nonce_len + self.nonce + timestamp_len + timestamp

        self.socket.send(len(byted_msg2).to_bytes(4, byteorder='big'))
        self.socket.send(byted_msg2)
        print("msg2 sent!")

        msg3_size_raw = self.socket.recv(4)
        msg3_size = int.from_bytes(msg3_size_raw, "big")
        msg3_raw = self.socket.recv(msg3_size)
        print("Received msg3!")
        isSuccess = msg3_raw[0]
        if isSuccess:
            ts_len = int.from_bytes(msg3_raw[1:5], "big")
            ts = msg3_raw[5:5+ts_len]
            return ts
        else:
            return None

    def get_timestamp(self):
        byted_id = bytes(self.id, 'ascii')
        id_len = len(byted_id).to_bytes(4, byteorder='big')
        byted_appId = bytes(self.appId, 'ascii')
        appId_len = len(byted_appId).to_bytes(4, byteorder='big')
        byted_operation = (2).to_bytes(4, byteorder='big')

        byted_msg0 = byted_operation + id_len + byted_id + appId_len + byted_appId
        self.socket.send(len(byted_msg0).to_bytes(4, byteorder='big'))
        self.socket.send(byted_msg0)
        print("msg0 sent!")
        msg1_size_raw = self.socket.recv(4)
        msg1_size = int.from_bytes(msg1_size_raw, "big")
        #print("msg1 size:", msg1_size)
        msg1_raw = self.socket.recv(msg1_size)
        print("Received msg1!")
        ts1_len = int.from_bytes(msg1_raw[0:4], "big")
        ts1 = msg1_raw[4:4+ts1_len]
        #nonce_size_raw = self.socket.recv(4)
        #nonce_size = int.from_bytes(nonce_size_raw, "big")
        #nonce_raw = self.socket.recv(nonce_size)
        #print("msg1 parsed!")
        return ts1

    def __init__(self, mqtt_id, app_id, evidence, nonce):
        self.id = mqtt_id
        self.appId = app_id
        self.evidence = evidence
        self.nonce = nonce
        #print(evidence)
        #self.sec_version = sec_version
        #self.product_id = product_id
        #self.claim = claim
        #self.mrEnclave = mrEnclave
        #self.mrSigner = mrSigner

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = "localhost" #"dustberry.panda-ling.ts.net"
        port = 2501
        self.socket.connect((host, port))


if __name__ == '__main__':
    with open('evidence.json', 'r') as file:
        mqtt_stub = MQTTStub("vedliot1", "app1", file.read().rstrip(), bytes.fromhex("210D7A62FAC071AD922AE07B28FECAD2364D75E191CFCDC9EE5B7BEA6FAB3E10"))
        mqtt_stub.mqtt_attest()
    #mqtt_stub = MQTTStub("vedliot1", "app1", 0, 0, bytes("measure1", 'ascii'), bytes("This is my nonce\0", 'ascii'), bytes("enclave1", 'ascii'), bytes("signer1", 'ascii'))
