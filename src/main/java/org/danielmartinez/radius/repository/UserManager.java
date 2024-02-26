package org.danielmartinez.radius.repository;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import java.security.MessageDigest;

public class UserManager {
    // HashMap to store user-password pairs
    private final Map<String, byte[]> userPasswordRepository;

    // HashMap to store client-sharedSecret pairs
    private final Map<String, byte[]> clientSharedSecretRepository;

    // Constructor
    public UserManager() {
        this.userPasswordRepository = new HashMap<>();
        this.clientSharedSecretRepository = new HashMap<>();
        setUp();
    }

    // Method that inserts some data when initializing UserManager
    public void setUp(){
        addUser("frans1", "fran123!".getBytes());
        addUser("frans2", "fran123!".getBytes());

        addClient("HARDCODED_CLIENTID", "ABC".getBytes());
    }

    // Method to add a user-password pair to the repository
    public void addUser(String username, byte[] password) {
        userPasswordRepository.put(username, password);
    }

    // Method to add a client-sharedSecret pair to the repository
    public void addClient(String clientId, byte[] sharedSecret) {
        clientSharedSecretRepository.put(clientId, sharedSecret);
    }

    // Method to authenticate a user
    public byte[] getPassword(String username) {
        return userPasswordRepository.get(username);
    }

    // Method to retrieve the shared secret for a client
    public byte[] getSharedSecret(String clientId) {
        return clientSharedSecretRepository.get(clientId);
    }

    // Method to check if a client exists
    public boolean clientExists(String clientId) {
        return clientSharedSecretRepository.containsKey(clientId);
    }

    // Method to check if a user exists
    public boolean userExists(String username) {
        return userPasswordRepository.containsKey(username);
    }

    /**
     *
     * @param username
     * @param clientHash
     * @param requestAuthenticator
     * @param sharedSecret
     * @return
     */
    public boolean isUserAuthenticated(byte[] username, byte[] clientHash, byte[] requestAuthenticator, byte[] sharedSecret){
        byte[] plainPassword;

        // Get User Password
        if(!userExists(new String(username))){
            System.out.println("Access-Reject. Reason: Unknown USER_NAME");
            return false;
        }

        else{
            plainPassword = getPassword(new String(username));
        }

        // Get HashMD5
        byte[] serverHash = encodePassword(plainPassword, requestAuthenticator, sharedSecret);

        // Validate Hash
        return validateHash(clientHash, serverHash);
    }

    /**
     *
     * @param clientHash
     * @param serverHash
     * @return
     */
    public boolean validateHash(byte[] clientHash, byte[] serverHash){
        return Arrays.equals(clientHash, serverHash);
    }

    /**
     *
     * @param plainPassword
     * @param requestAuthenticator
     * @param sharedSecret
     * @return
     */
    public byte[] encodePassword(byte[] plainPassword, byte[] requestAuthenticator, byte[] sharedSecret) {
        byte[] encodedPassword;

        if (plainPassword.length % 16 == 0) {
            encodedPassword = new byte[plainPassword.length];
        } else {
            int paddingBytes = 16 - (plainPassword.length % 16);
            encodedPassword = new byte[plainPassword.length + paddingBytes];
        }

        System.arraycopy(plainPassword, 0, encodedPassword, 0, plainPassword.length);

        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] bn = new byte[sharedSecret.length + requestAuthenticator.length];

            for (int i = 0; i < bn.length; i++) {
                if (i < sharedSecret.length)
                    bn[i] = sharedSecret[i];
                else
                    bn[i] = requestAuthenticator[i - sharedSecret.length];
            }

            md5.update(bn);
            bn = md5.digest();

            for (int i = 0; i < 16; i++) {
                encodedPassword[i] = (byte) (bn[i] ^ encodedPassword[i]);
            }

            if (encodedPassword.length > 16) {
                for (int i = 16; i < encodedPassword.length; i += 16) {
                    md5.reset();
                    md5.update(sharedSecret);
                    // add the previous (encrypted) 16 bytes of the user password
                    md5.update(encodedPassword, i - 16, 16);
                    bn = md5.digest();
                    // perform the XOR as specified by RFC 2865.
                    for (int j = 0; j < 16; j++) {
                        encodedPassword[i + j] = (byte) (bn[j] ^ encodedPassword[i + j]);
                    }
                }
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return encodedPassword;
    }
}
