package org.danielmartinez.radius.packet;

import org.danielmartinez.radius.packet.attribute.Attribute;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/**
 * This class represents a RADIUS Packet following the RFC 2865 guidelines
 */
public class RadiusPacket {

    /**
     * Code field: It identifies the type of RADIUS packet
     * - 1 byte
     * - Values in range [0 - 255]
     */
    private short code;

    /**
     * Identifier field: It aids in matching requests and replies
     * - 1 byte
     * - Values in range [0 - 255]
     */
    private short identifier;

    /**
     * Length field: It indicates the length of the packet including the Code, Identifier, Length,
     * Authenticator and Attribute fields
     * - 2 bytes
     * - Values in range [20 - 4096]
     */
    private int length;

    /**
     * Authenticator field: It is used to authenticate the reply from the RADIUS server, and is used in the
     * password hiding algorithm
     * - 16 bytes
     */
    private byte[] authenticator;

    /**
     * Attributes field: It contains a list of zero or more Attributes, detailed in Attribute class
     * - Variable length
     */
    private List<Attribute> attributes;

    // Constructor
    public RadiusPacket(short code, short identifier, int length, byte[] authenticator, List<Attribute> attributes) {
        this.code = code;
        this.identifier = identifier;
        this.length = length;
        this.authenticator = authenticator;
        this.attributes = attributes;
    }

    // Getters and Setters
    public short getCode() {
        return code;
    }
    public void setCode(short code) {
        this.code = code;
    }

    public short getIdentifier() {
        return identifier;
    }
    public void setIdentifier(short identifier) {
        this.identifier = identifier;
    }

    public int getLength() {
        return length;
    }
    public void setLength(short length) {
        this.length = length;
    }

    public byte[] getAuthenticator() {
        return authenticator;
    }
    public void setAuthenticator(byte[] authenticator) {
        this.authenticator = authenticator;
    }

    public List<Attribute> getAttributes() { return attributes; }
    public void setAttributes(List<Attribute> attributes) { this.attributes = attributes; }

    @Override
    public String toString() {
        return "RadiusPacket{" +
                "code=" + code +
                ", identifier=" + identifier +
                ", length=" + length +
                ", authenticator=" + Arrays.toString(authenticator) +
                ", attributes=" + attributes +
                '}';
    }

    public void setAuthenticationResponse (RadiusPacket receivedRadiusPacket) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Add RADIUS attributes
        dos.writeByte(this.getCode());
        dos.writeByte(this.getIdentifier());
        dos.writeShort(this.getLength());
        dos.write(receivedRadiusPacket.getAuthenticator());
        dos.write("ABC".getBytes());

        dos.flush();
        byte[] hashBody = baos.toByteArray();

        try{
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(hashBody);
            this.setAuthenticator(md5.digest());

        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        dos.close();
        baos.close();
    }
}
