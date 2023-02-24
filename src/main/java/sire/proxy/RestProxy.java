/*
 * Copyright 2023 Tiago Carvalho
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sire.proxy;

import com.google.protobuf.ByteString;
import confidential.ConfidentialExtractedResponse;
import confidential.client.ConfidentialServiceProxy;
import confidential.client.Response;
import org.bouncycastle.math.ec.ECPoint;
import sire.attestation.Evidence;
import sire.management.AppManager;
import sire.attestation.Policy;
import sire.messages.Messages;
import sire.membership.DeviceContext;
import sire.messages.RESTResponses;
import sire.schnorr.PublicPartialSignature;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;
import sire.serverProxyUtils.SireException;
import vss.commitment.ellipticCurve.EllipticCurveCommitment;
import vss.facade.SecretSharingException;
import vss.secretsharing.Share;
import vss.secretsharing.VerifiableShare;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static sire.messages.ProtoUtils.*;

public class RestProxy  {
    private final ConfidentialServiceProxy serviceProxy;
    private static MessageDigest messageDigest;
    private final ECPoint verifierPublicKey;
    private final SchnorrSignatureScheme signatureScheme;

    public RestProxy(int proxyId) throws SireException {
        try {
            ServersResponseHandlerWithoutCombine responseHandler = new ServersResponseHandlerWithoutCombine();
            serviceProxy = new ConfidentialServiceProxy(proxyId, responseHandler);
            messageDigest = MessageDigest.getInstance("SHA256");
        } catch (SecretSharingException | NoSuchAlgorithmException e) {
            throw new SireException("Failed to contact the distributed verifier", e);
        }

        try {
            signatureScheme = new SchnorrSignatureScheme();
        } catch (NoSuchAlgorithmException e) {
            throw new SireException("Failed to initialize cryptographic tools", e);
        }
        Response response;
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.ATTEST_GET_PUBLIC_KEY)
                    .build();
            byte[] b = msg.toByteArray();
            response = serviceProxy.invokeOrdered(b);//new byte[]{(byte) Operation.GENERATE_SIGNING_KEY.ordinal()});
        } catch (SecretSharingException e) {
            throw new SireException("Failed to obtain verifier's public key", e);
        }
        verifierPublicKey = signatureScheme.decodePublicKey(response.getPainData());
    }

    public void addExtension(String key, String code) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.EXTENSION_ADD)
                    .setKey(key)
                    .setCode(code)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }

    public void removeExtension(String key) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.EXTENSION_REMOVE)
                    .setKey(key)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public String getExtension(String key) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.EXTENSION_GET)
                    .setKey(key)
                    .build();
            Response res = serviceProxy.invokeOrdered(msg.toByteArray());

            return (String) deserialize(res.getPainData());
        } catch(SecretSharingException | IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }


    public void setPolicy(String appId, String policy, boolean type) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.POLICY_ADD)
                    .setAppId(appId)
                    .setPolicy(Messages.ProxyMessage.ProtoPolicy.newBuilder()
                            .setType(type)
                            .setPolicy(policy)
                            .build())
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public void deletePolicy(String appId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.POLICY_REMOVE)
                    .setAppId(appId)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public Policy getPolicy(String appId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.POLICY_GET)
                    .setAppId(appId)
                    .build();
            Response res = serviceProxy.invokeOrdered(msg.toByteArray());

            return new Policy((String) deserialize(res.getPainData()), false);
        } catch(SecretSharingException | IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }


    public RESTResponses.preJoinResponse getTimestamp(String appId, byte[] attesterPubKey, SchnorrSignature schnorrSignature) {
        try {
            Messages.ProxyMessage timestampMsg = Messages.ProxyMessage.newBuilder()
                    .setAppId(appId)
                    .setOperation(Messages.ProxyMessage.Operation.ATTEST_TIMESTAMP)
                    .setPubKey(ByteString.copyFrom(attesterPubKey))
                    .setSignature(schnorrToProto(schnorrSignature))
                    .build();

            ConfidentialExtractedResponse res = serviceProxy.invokeOrdered2(timestampMsg.toByteArray());
            SchnorrSignature sign = combineSignatures((UncombinedConfidentialResponse) res);
            byte[] data = Arrays.copyOfRange(res.getPlainData(), res.getPlainData().length - 124, res.getPlainData().length);
            byte[] ts = Arrays.copyOfRange(data, 0, 91);
            byte[] pubKey = Arrays.copyOfRange(data, 91, data.length);
            Base64.Encoder enc = Base64.getEncoder();
            return new RESTResponses.preJoinResponse(enc.encodeToString(pubKey), enc.encodeToString(ts), enc.encodeToString(sign.getSigma()),
                    enc.encodeToString(sign.getSigningPublicKey()), enc.encodeToString(sign.getRandomPublicKey()));
        } catch(SecretSharingException | SireException e) {
            e.printStackTrace();
        }
        return null;
    }

    private SchnorrSignature combineSignatures (UncombinedConfidentialResponse res) throws SireException {
        PublicPartialSignature partialSignature;
        byte[] signs = Arrays.copyOfRange(res.getPlainData(), 0, 199);
        //System.out.println(Arrays.toString(signs));
        try (ByteArrayInputStream bis = new ByteArrayInputStream(signs);
             ObjectInput in = new ObjectInputStream(bis)) {
            partialSignature = PublicPartialSignature.deserialize(signatureScheme, in);
        } catch (IOException | ClassNotFoundException e) {
            throw new SireException("Failed to deserialize public data of partial signatures");
        }
        EllipticCurveCommitment signingKeyCommitment = partialSignature.getSigningKeyCommitment();
        EllipticCurveCommitment randomKeyCommitment = partialSignature.getRandomKeyCommitment();
        ECPoint randomPublicKey = partialSignature.getRandomPublicKey();
        VerifiableShare[] verifiableShares = res.getVerifiableShares()[0];
        Share[] partialSignatures = new Share[verifiableShares.length];
        for (int i = 0; i < verifiableShares.length; i++) {
            partialSignatures[i] = verifiableShares[i].getShare();
        }

        if (randomKeyCommitment == null)
            throw new IllegalStateException("Random key commitment is null");

        byte[] data = Arrays.copyOfRange(res.getPlainData(), 199, res.getPlainData().length);

        try {
            BigInteger sigma = signatureScheme.combinePartialSignatures(
                    serviceProxy.getCurrentF(),
                    data,
                    signingKeyCommitment,
                    randomKeyCommitment,
                    randomPublicKey,
                    partialSignatures
            );
            return new SchnorrSignature(sigma.toByteArray(), verifierPublicKey.getEncoded(true),
                    randomPublicKey.getEncoded(true));
        } catch (SecretSharingException e) {
            throw new SireException("Failed to combine partial signatures", e);
        }
    }


    public RESTResponses.JoinResponse join(String appId, Evidence evidence, Timestamp ts, SchnorrSignature sign, byte[] attesterPublicKey) {
        try {
            Messages.ProxyMessage joinMsg = Messages.ProxyMessage.newBuilder()
                    .setAppId(appId)
                    .setOperation(Messages.ProxyMessage.Operation.MEMBERSHIP_JOIN)
                    .setDeviceId(bytesToHex(computeHash(attesterPublicKey)))
                    .setEvidence(evidenceToProto(evidence))
                    .setTimestamp(ByteString.copyFrom(serialize(ts)))
                    .setPubKey(ByteString.copyFrom(attesterPublicKey))
                    .setSignature(schnorrToProto(sign))
                    .build();
            ConfidentialExtractedResponse res = serviceProxy.invokeOrdered2(joinMsg.toByteArray());

            byte[] data = Arrays.copyOfRange(res.getPlainData(), res.getPlainData().length - 156, res.getPlainData().length);
            byte[] time = Arrays.copyOfRange(data, 0, 91);
            byte[] pubKey = Arrays.copyOfRange(data, 91, 124);
            byte[] hash = Arrays.copyOfRange(data, 124, data.length);
            Base64.Encoder enc = Base64.getEncoder();
            return new RESTResponses.JoinResponse(enc.encodeToString(pubKey), enc.encodeToString(time), enc.encodeToString(hash),
                    enc.encodeToString(sign.getSigma()), enc.encodeToString(sign.getSigningPublicKey()),
                    enc.encodeToString(sign.getRandomPublicKey()));
        } catch (IOException | SecretSharingException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static byte[] computeHash(byte[]... contents) {
        for (byte[] content : contents) {
            messageDigest.update(content);
        }
        return messageDigest.digest();
    }


    public void leave(String appId, String deviceId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MEMBERSHIP_LEAVE)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public void ping(String appId, String deviceId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MEMBERSHIP_PING)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public List<DeviceContext> getView(String appId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MEMBERSHIP_VIEW)
                    .setAppId(appId)
                    .build();
            Response res = serviceProxy.invokeOrdered(msg.toByteArray());

            byte[] tmp = res.getPainData();
            if (tmp != null) {
                ByteArrayInputStream bin = new ByteArrayInputStream(tmp);
                ObjectInputStream oin = new ObjectInputStream(bin);
                return (List<DeviceContext>) oin.readObject();
            } else
                return null;
        } catch(SecretSharingException | IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }


    public List<String> getApps(String admin) {
        return AppManager.getInstance().getAppsFromAdmin(admin);
    }


    public void put(String appId, String deviceId, String key, byte[] value) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MAP_PUT)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .setKey(key)
                    .setValue(ByteString.copyFrom(value))
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public void delete(String appId, String deviceId, String key) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MAP_DELETE)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .setKey(key)
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


    public byte[] get(String appId, String deviceId, String key) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MAP_PUT)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .setKey(key)
                    .build();
            return serviceProxy.invokeOrdered(msg.toByteArray()).getPainData();
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
        return null;
    }


    public List<byte[]> getList(String appId, String deviceId) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MAP_LIST)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .build();
            byte[] tmp = serviceProxy.invokeOrdered(msg.toByteArray()).getPainData();
            ArrayList<byte[]> res = null;
            if (tmp != null) {
                ByteArrayInputStream bin = new ByteArrayInputStream(tmp);
                ObjectInputStream oin = new ObjectInputStream(bin);
                res = (ArrayList<byte[]>) oin.readObject();
            }
            return res;
        } catch (IOException | ClassNotFoundException | SecretSharingException e) {
            e.printStackTrace();
        }
        return null;
    }


    public void cas(String appId, String deviceId, String key, byte[] oldValue, byte[] newValue) {
        try {
            Messages.ProxyMessage msg = Messages.ProxyMessage.newBuilder()
                    .setOperation(Messages.ProxyMessage.Operation.MAP_PUT)
                    .setAppId(appId)
                    .setDeviceId(deviceId)
                    .setKey(key)
                    .setValue(ByteString.copyFrom(newValue))
                    .setOldData(ByteString.copyFrom(oldValue))
                    .build();
            serviceProxy.invokeOrdered(msg.toByteArray());
        } catch(SecretSharingException e) {
            e.printStackTrace();
        }
    }


}
