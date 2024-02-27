package org.danielmartinez.radius.packet;

import java.util.Arrays;

/**
 * This class represents each Attribute that composes the Attributes field in a RADIUS packet
 */
public class Attribute {
    /**
     * Type field: It identifies the type of RADIUS attribute
     * Length: 1 Byte
     */
    private int type;

    /**
     * Length field: It indicates the length of this attribute including the Type, Length and Value fields.
     * Length: 1 Byte
     */
    private int length;

    /**
     * Value field: It contains information specific to the Attribute
     * Length: 0 or more bytes.
     */
    private byte[] value;

    // Constructor
    public Attribute(int type, int length, byte[] value) {
        this.type = type;
        this.length = length;
        this.value = value;
    }

    // Constructor
    public Attribute() {
    }

    // Getters and setters
    public int getType() { return type; }
    public void setType(int type) {
        this.type = type;
    }

    public int getLength() {
        return length;
    }
    public void setLength(int length) {
        this.length = length;
    }

    public byte[] getValue() {return value; }
    public void setValue(byte[] value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return "[" +
                "type=" + type +
                ", length=" + length +
                ", value=" + Arrays.toString(value) +
                ']';
    }
}
