package com.hostencryption.model;

final public class RequestData {

    private final String activationData;
    private final String ephemeralPublicKey;
    private final String encryptedData;

    public RequestData(String activationData, String ephemeralPublicKey, String encryptedData) {
        this.activationData = activationData;
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.encryptedData = encryptedData;
    }

    public String getActivationData() {
        return activationData;
    }

    public String getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public String getEncryptedData() {
        return encryptedData;
    }

    @Override
    public String toString() {
        return "{\n" +
                "\t\"activationData\": \"" + activationData + "\",\n" +
                "\t\"ephemeralPublicKey\": \"" + ephemeralPublicKey + "\",\n" +
                "\t\"encryptedData\": \"" + encryptedData + "\",\n" +
                '}';
    }
}
