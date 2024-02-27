package org.danielmartinez.radius.repository;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import java.security.MessageDigest;

/**
 * This class implements all the logic related to the User Authentication
 */
public class UserManager {
    /**
     * HashMap to store user-password pairs, simulating a Database
     */
    private final Map<String, byte[]> userPasswordRepository;

    /**
     * HashMap to store client-sharedSecret pairs, simulating a Database
     */
    private final Map<String, byte[]> clientSharedSecretRepository;

    // Constructor
    public UserManager() {
        this.userPasswordRepository = new HashMap<>();
        this.clientSharedSecretRepository = new HashMap<>();
        setUp();
    }

    /**
     * This method inserts some data when initializing UserManager
     */
    public void setUp(){
        addUser("frans1", "fran123!".getBytes());
        addUser("frans2", "fran123!".getBytes());

        addClient("HARDCODED_CLIENTID", "ABC".getBytes());
    }

    /**
     * Method to add a user-password pair to the repository
     * @param username username
     * @param password password
     */
    public void addUser(String username, byte[] password) {
        userPasswordRepository.put(username, password);
    }

    /**
     * Method to add a client-sharedSecret pair to the repository
     * @param clientId clientId
     * @param sharedSecret sharedSecret
     */
    public void addClient(String clientId, byte[] sharedSecret) {
        clientSharedSecretRepository.put(clientId, sharedSecret);
    }

    /**
     * Method to authenticate a user
     * @param username username
     * @return password
     */
    public byte[] getPassword(String username) {
        return userPasswordRepository.get(username);
    }

    /**
     * Method to retrieve the shared secret for a client
     * @param clientId clientId
     * @return sharedSecret
     */
    public byte[] getSharedSecret(String clientId) {
        return clientSharedSecretRepository.get(clientId);
    }

    /**
     * Method to check if a client exists
     * @param clientId clientId
     * @return boolean: True if exists
     */
    public boolean clientExists(String clientId) {
        return clientSharedSecretRepository.containsKey(clientId);
    }

    /**
     * Method to check if a user exists
     * @param username username
     * @return boolean: True if exists
     */
    public boolean userExists(String username) {
        return userPasswordRepository.containsKey(username);
    }

    /**
     * This method checks if a user is authenticated in the Server Database
     * @param username Username
     * @param clientHash The Hash provided by the received Packet which includes the encrypted password
     * @param requestAuthenticator Request Authenticator field
     * @param sharedSecret Shared Secret between the RADIUS Client and the Server
     * @return Boolean: True if it is authenticated
     */
    public boolean isUserAuthenticated(byte[] username, byte[] clientHash, byte[] requestAuthenticator, byte[] sharedSecret){
        byte[] plainPassword;

        // Get User Password
        if(!userExists(new String(username))){
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
     * This method encodes a password by using the RADIUS method defined in the RFC 2865, using MD5 as the hashing
     * algoithm. The server calculates the hash with the user credentials and check if it matches the hash provided by
     * the user/client
     * @param plainPassword Plain user password, obtained in the Server database
     * @param requestAuthenticator Request Authenticator field, provided by the user
     * @param sharedSecret Shared Secret between the RADIUS Client and the Server
     * @return The encoded password / hash in byte[] format
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

    /**
     * This method checks if the received hash and the hash calculated in the server side are equal
     * @param clientHash Hash provided by the Client
     * @param serverHash Hash calculated by the Server
     * @return Boolean: True if it is equal
     */
    public boolean validateHash(byte[] clientHash, byte[] serverHash){
        return Arrays.equals(clientHash, serverHash);
    }
}
