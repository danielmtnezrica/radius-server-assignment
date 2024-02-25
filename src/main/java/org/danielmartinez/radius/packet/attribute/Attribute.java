package org.danielmartinez.radius.packet.attribute;

import java.util.Arrays;

/**
 * This class represents each Attribute that composes the Attributes field in a RADIUS packet
 */
public class Attribute {
    /**
     * Type field: It identifies the type of RADIUS attribute
     * - 1 byte
     */
    private short type;

    /**
     * Length field: It indicates the length of this attribute including the Type, Length and Value fields.
     * - 1 byte
     */
    private int length;

    /**
     * Value field: It contains information specific to the Attribute
     * - 0 or more bytes.
     * *NOTE: In this implementation, we only consider that this value follows 'string-1' format,
     * which is composed of maximum 253 octets composed of binary data
     */
    private byte[] value;

    // Constructor
    public Attribute(short type, int length, byte[] value) {
        this.type = type;
        this.length = length;
        this.value = value;
    }

    public Attribute() {
    }

    // Getters and setters
    public short getType() { return type; }
    public void setType(short type) {
        this.type = type;
    }

    public int getLength() {
        return length;
    }
    public void setLength(short length) {
        this.length = length;
    }

    public byte[] getValue() {
        return value;
    }
    public void setValue(byte[] value) {
        this.value = value;
    }


    @Override
    public String toString() {
        return "Attribute{" +
                "type=" + type +
                ", length=" + length +
                ", value=" + Arrays.toString(value) +
                '}';
    }
}
