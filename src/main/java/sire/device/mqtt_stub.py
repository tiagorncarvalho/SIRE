import socket
import schnorr
import hashlib

class MQTTStub:
        
    def compute_claim(self, nonce):
        m = hashlib.sha256()
        m.update(self.claim)
        claim_hash = m.digest()
        
        m2 = hashlib.sha256()
        m2.update(claim_hash)
        m2.update(bytes(nonce, 'ascii'))
        return m2.digest()
        
    def join(self, timestamp, nonce):
        byted_operation = (9).to_bytes(4, byteorder='big')
        byted_id = bytes(self.id, 'ascii')
        id_len = len(byted_id).to_bytes(4, byteorder='big')
        byted_appId = bytes(self.appId, 'ascii')
        appId_len = len(byted_appId).to_bytes(4, byteorder='big')
        byted_sec_version = self.sec_version.to_bytes(4, byteorder='big')
        byted_product_id = self.product_id.to_bytes(4, byteorder='big')
        comp_claim = self.compute_claim(nonce)
        comp_claim_len = len(comp_claim).to_bytes(4, byteorder='big')
        byted_nonce = bytes(nonce, 'ascii')
        nonce_len = len(byted_nonce).to_bytes(4, byteorder='big')
        mrEnclave_len = len(self.mrEnclave).to_bytes(4, byteorder='big')
        mrSigner_len = len(self.mrSigner).to_bytes(4, byteorder='big')
        timestamp_len = len(timestamp).to_bytes(4, byteorder='big')
        
        byted_msg2 = byted_operation + id_len + byted_id + appId_len + byted_appId + byted_sec_version + byted_product_id + comp_claim_len + comp_claim + nonce_len + byted_nonce + mrEnclave_len + self.mrEnclave + mrSigner_len + self.mrSigner + timestamp_len + timestamp
        
        self.socket.send(len(byted_msg2).to_bytes(4, byteorder='big'))
        self.socket.send(byted_msg2)
        print("msg2 sent!")
        
        msg3_size_raw = self.socket.recv(4)
        msg3_size = int.from_bytes(msg3_size_raw, "big")
        msg3_raw = self.socket.recv(msg3_size)
        print("Received msg3!")
        ts_len = int.from_bytes(msg3_raw[0:4], "big")
        ts = msg3_raw[4:4+ts_len]
        return ts
        
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
        nonce_size_raw = self.socket.recv(4)
        nonce_size = int.from_bytes(nonce_size_raw, "big")
        nonce_raw = self.socket.recv(nonce_size)
        #print("msg1 parsed!")
        return ts1, str(nonce_raw, 'ascii')
    
    def __init__(self, mqtt_id, app_id, sec_version, product_id, claim, mrEnclave, mrSigner):
        self.id = mqtt_id
        self.appId = app_id
        self.sec_version = sec_version
        self.product_id = product_id
        self.claim = claim
        self.mrEnclave = mrEnclave
        self.mrSigner = mrSigner
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = "localhost" #"dustberry.panda-ling.ts.net"
        port = 3602
        self.socket.connect((host, port))
        
        
if __name__ == '__main__':
    mqtt_stub = MQTTStub("vedliot1", "app1", 0, 0, bytes("measure1", 'ascii'), bytes("enclave1", 'ascii'), bytes("signer1", 'ascii'))
    ts1, nonce = mqtt_stub.get_timestamp()
    attestation_time = mqtt_stub.join(ts1, nonce)
    print("MQTT attested!\n")