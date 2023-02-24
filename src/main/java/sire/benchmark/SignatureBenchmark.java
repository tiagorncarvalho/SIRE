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

package sire.benchmark;

import org.bouncycastle.math.ec.ECPoint;
import sire.schnorr.SchnorrSignature;
import sire.schnorr.SchnorrSignatureScheme;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

public class SignatureBenchmark {
    private static MessageDigest messageDigest;
    private static SchnorrSignatureScheme scheme;

    static {
        try {
            messageDigest = MessageDigest.getInstance("SHA256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) throws NoSuchAlgorithmException {
        if (args.length != 2) {
            System.out.println("USAGE: ... sire.benchmark.SignatureBenchmark " +
                    "<warm up iterations> <test iterations> ");
            System.exit(-1);
        }
        int wIterations = Integer.parseInt(args[0]);
        int tIterations = Integer.parseInt(args[1]);

        scheme = new SchnorrSignatureScheme();

        System.out.println("Warming up (" + wIterations + " iterations)");
        if (wIterations > 0)
            runTests(wIterations, false);
        System.out.println("Running test (" + tIterations + " iterations)");
        if (tIterations > 0)
            runTests(tIterations, true);

    }

    private static void runTests(int nTests, boolean printResults){
        BigInteger signPrivateKey = new BigInteger("4049546346519992604730332816858472394381393488413156548605745581385");
        ECPoint signPubKey = scheme.getGenerator().multiply(signPrivateKey);

        BigInteger randomPrivateKey = new BigInteger("2673E6E0D6F66A15DB4FA597B8160F23AB8767ED0E46692E01E04D49BD154426", 16);
        ECPoint randomPublicKey = scheme.getGenerator().multiply(randomPrivateKey);
        byte[] d = new byte[200];
        new Random().nextBytes(d);

        long start, end;
        long[] signingTimes = new long[nTests];
        long[] verificationTimes = new long[nTests];

        for (int nT = 0; nT < nTests; nT++) {
            start = System.nanoTime();
            scheme.computeSignature(d, signPrivateKey, signPubKey, randomPrivateKey, randomPublicKey);
            end = System.nanoTime();
            signingTimes[nT] = end - start;

            SchnorrSignature sign = scheme.computeSignature(d, signPrivateKey, signPubKey, randomPrivateKey, randomPublicKey);

            start = System.nanoTime();
            scheme.verifySignature(d, scheme.decodePublicKey(sign.getSigningPublicKey()), scheme.decodePublicKey(sign.getRandomPublicKey()), new BigInteger(sign.getSigma()));
            end = System.nanoTime();
            verificationTimes[nT] = end - start;

        }

        if(printResults) {
            double signAverage = computeAverage(signingTimes);
            double verifyAverage = computeAverage(verificationTimes);

            System.out.println("Sign: " + signAverage + " ms");
            System.out.println("Verify: " + verifyAverage + " ms");
        }
    }

    private static double computeAverage(long[] values) {
        return ((double) Arrays.stream(values).sum() / values.length) / 1_000_000.0;
    }

    private static byte[][] generateData(int nVer) {
        byte[][] res = new byte[nVer][];
        for(int i = 0; i < nVer; i++) {
            res[i] = new byte[200];
            new Random().nextBytes(res[i]);
        }
        return res;
    }
}
