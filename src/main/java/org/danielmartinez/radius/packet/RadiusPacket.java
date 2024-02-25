package org.danielmartinez.radius.packet;

import org.danielmartinez.radius.packet.attribute.Attribute;

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

    // Code 1: Access-Request
    private final short ACCESS_REQUEST_CODE = 1;

    // Code 2: Access-Accept
    private final short ACCESS_ACCEPT_CODE = 2;

    // Code 3: Access-Reject
    private final short ACCESS_REJECT_CODE = 3;

    // Code 4: Accounting-Request
    private final short ACCOUNTING_REQUEST_CODE = 4;

    // Code 5: Accounting-Response
    private final short ACCOUNTING_RESPONSE_CODE = 5;

    // Code 11: Access-Challenge
    private final short ACCESS_CHALLENGE_CODE = 11;

    // Code 12: Status-Server (experimental)
    private final short STATUS_SERVER_CODE = 12;

    // Code 13: Status-Client (experimental)
    private final short STATUS_CLIENT_CODE = 13;

    // Code 255: Reserved
    private final short RESERVED_CODE = 255;

    /**
     * Identifier field: It aids in matching requests and replies
     * - 2 bytes
     * - Values in range [20 - 4096]
     */
    private short identifier;

    /**
     * Length field: It indicates the length of the packet including the Code, Identifier, Length,
     * Authenticator and Attribute fields
     * - 1 byte
     * - Values in range [0 - 255]
     */
    private short length;

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
    public RadiusPacket(short code, short identifier, short length, byte[] authenticator, List<Attribute> attributes) {
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

    public short getLength() {
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
}
