package org.danielmartinez.radius.packet;

import org.danielmartinez.radius.util.RadiusConstants;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This class represents a RADIUS Packet following the RFC 2865 guidelines
 */
public class RadiusPacket {

    /**
     * Code field: It identifies the type of RADIUS packet
     * Length: 1 Byte
     * Values: Range [0 - 255]
     */
    private int code;

    /**
     * Identifier field: It aids in matching requests and replies
     * Length: 1 Byte
     * Values: Range [0 - 255]
     */
    private int identifier;

    /**
     * Length field: It indicates the length of the packet including the Code, Identifier, Length, Authenticator and Attribute fields
     * Length: 2 Bytes
     * Values Range [20 - 4096]
     */
    private int length;

    /**
     * Authenticator field: It is used to authenticate the reply from the RADIUS server, and is used in the
     * password hiding algorithm
     * Length: 16 Bytes
     */
    private byte[] authenticator;

    /**
     * Attributes field: It contains a list of zero or more Attributes, detailed in Attribute class
     * Length: Variable
     */
    private List<Attribute> attributes;

    // Constructor
    public RadiusPacket(int code, int identifier, int length, byte[] authenticator, List<Attribute> attributes) {
        this.code = code;
        this.identifier = identifier;
        this.length = length;
        this.authenticator = authenticator;
        this.attributes = attributes;
    }

    // Constructor
    public RadiusPacket(int code, int identifier, byte[] authenticator) {
        this.code = code;
        this.identifier = identifier;
        this.length = 0;
        this.authenticator = authenticator;
        this.attributes = new ArrayList<>();
    }

    // Getters and Setters
    public int getCode() { return code; }
    public void setCode(int code) { this.code = code; }

    public int getIdentifier() { return identifier; }
    public void setIdentifier(int identifier) { this.identifier = identifier; }

    public int getLength() { return length; }
    public void setLength(int length) { this.length = length; }

    public byte[] getAuthenticator() { return authenticator; }
    public void setAuthenticator(byte[] authenticator) { this.authenticator = authenticator; }

    public List<Attribute> getAttributes() { return attributes; }
    public void setAttributes(List<Attribute> attributes) { this.attributes = attributes; }

    public void setAttribute(int type, int length, byte[] value){
        Attribute attribute = new Attribute(type, length, value);
        attribute.setLength((2 + value.length));
        this.attributes.add(attribute);
    }

    @Override
    public String toString() {
        return "[" +
                "code=" + code +
                ", identifier=" + identifier +
                ", length=" + length +
                ", authenticator=" + Arrays.toString(authenticator) +
                ", attributes=" + attributes +
                ']';
    }

    /**
     * This method calculates and sets the Authenticator Response field
     * @param receivedRadiusPacket Received RADIUS Packet that triggers the response
     * @param sharedSecret Shared Secret between RADIUS Client and Server
     */
    public void setAuthenticatorResponse(RadiusPacket receivedRadiusPacket, byte[] sharedSecret,
                                         List<Attribute> responseAttributes){
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        try {
            dos.writeByte(this.getCode());
            dos.writeByte(this.getIdentifier());
            dos.writeShort(this.getLength());
            dos.write(receivedRadiusPacket.getAuthenticator());

            for(Attribute attribute: responseAttributes){
                dos.writeByte(attribute.getType());
                dos.writeByte(attribute.getLength());
                dos.write(attribute.getValue());
            }

            dos.write(sharedSecret);

            dos.flush();
            byte[] hashBody = baos.toByteArray();

            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(hashBody);
            this.setAuthenticator(md5.digest());

            dos.close();
            baos.close();

        } catch (IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This method transform RadiusPacket format into byte array (byte[]) format
     * @return The packet in byte array format
     */
    public byte[] toByteArray(){
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        try {
            dos.writeByte(this.getCode());
            dos.writeByte(this.getIdentifier());
            dos.writeShort(this.getLength());
            dos.write(this.getAuthenticator());

            for(Attribute attribute: this.attributes){
                dos.writeByte(attribute.getType());
                dos.writeByte(attribute.getLength());
                dos.write(attribute.getValue());
            }

            dos.flush();
            byte[] responsePacket = baos.toByteArray();
            dos.close();
            baos.close();

            return responsePacket;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This method calculates the length of a RadiusPacket based in all its fields
     * @return The length of the RadiusPacket
     */
    public int calculateLength(){
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        int radiusPacketLength;

        try {
            dos.writeByte(this.getCode());
            dos.writeByte(this.getIdentifier());
            dos.writeShort(this.getLength());
            dos.write(this.getAuthenticator());

            for(Attribute attribute: this.attributes){
                dos.writeByte(attribute.getType());
                dos.writeByte(attribute.getLength());
                dos.write(attribute.getValue());
            }

            dos.flush();
            byte[] bytePacket = baos.toByteArray();
            radiusPacketLength = bytePacket.length;
            dos.close();
            baos.close();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return radiusPacketLength;
    }

    /**
     * This method creates an Access-Accept RADIUS response
     * @param receivedRadiusPacket The received RADIUS Packet that triggers the response
     * @param sharedSecret Shared Secret between RADIUS Client and Server
     * @return Access-Accept RADIUS response
     */
    public static RadiusPacket createAccessAccept(RadiusPacket receivedRadiusPacket, byte[] sharedSecret){
        RadiusPacket accessAcceptPacket = new RadiusPacket(RadiusConstants.ACCESS_ACCEPT_CODE,
                receivedRadiusPacket.getIdentifier(), receivedRadiusPacket.getAuthenticator());

        accessAcceptPacket.setLength(accessAcceptPacket.calculateLength());
        accessAcceptPacket.setAuthenticatorResponse(receivedRadiusPacket, sharedSecret,
                accessAcceptPacket.getAttributes());

        return accessAcceptPacket;
    }

    /**
     * This method creates an Access-Reject RADIUS response
     * @param receivedRadiusPacket The received RADIUS Packet that triggers the response
     * @param sharedSecret Shared Secret between RADIUS Client and Server
     * @param reason The reason why the received RADIUS Packet is not accepted
     * @return Access-Reject RADIUS response
     */
    public static RadiusPacket createAccessReject(RadiusPacket receivedRadiusPacket, byte[] sharedSecret, String reason){
        RadiusPacket accessRejectPacket = new RadiusPacket(RadiusConstants.ACCESS_REJECT_CODE,
                receivedRadiusPacket.getIdentifier(), receivedRadiusPacket.getAuthenticator());

        accessRejectPacket.setLength(accessRejectPacket.calculateLength());

        // * NOTE: This line of code is used to send the reason to the client. As it is not processed by the
        // Test Client, it is not implemented
        // accessRejectPacket.setAttribute(RadiusConstants.REPLY_MESSAGE, 0, reason.getBytes());

        accessRejectPacket.setAuthenticatorResponse(receivedRadiusPacket, sharedSecret,
                accessRejectPacket.getAttributes());

        return accessRejectPacket;
    }
}
