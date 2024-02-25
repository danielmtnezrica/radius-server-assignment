package org.danielmartinez.radius.packet.attribute;

/**
 * This class represents each Attribute that composes the Attributes field in a RADIUS packet
 */
public class Attribute {
    /**
     * Type field: It identifies the type of RADIUS attribute
     * - 1 byte
     */
    private short type;

    // Type 1: User-Name
    private static final short USER_NAME = 1;

    // Type 2: User-Password
    private static final short USER_PASSWORD = 2;

    // Type 3: CHAP-Password
    private static final short CHAP_PASSWORD = 3;

    // Type 4: NAS-IP-Address
    private static final short NAS_IP_ADDRESS = 4;

    // Type 5: NAS-Port
    private static final short NAS_PORT = 5;

    // Type 6: Service-Type
    private static final short SERVICE_TYPE = 6;

    // Type 7: Framed-Protocol
    private static final short FRAMED_PROTOCOL = 7;

    // Type 8: Framed-IP-Address
    private static final short FRAMED_IP_ADDRESS = 8;

    // Type 9: Framed-IP-Netmask
    private static final short FRAMED_IP_NETMASK = 9;

    // Type 10: Framed-Routing
    private static final short FRAMED_ROUTING = 10;

    // Type 11: Filter-Id
    private static final short FILTER_ID = 11;

    // Type 12: Framed-MTU
    private static final short FRAMED_MTU = 12;

    // Type 13: Framed-Compression
    private static final short FRAMED_COMPRESSION = 13;

    // Type 14: Login-IP-Host
    private static final short LOGIN_IP_HOST = 14;

    // Type 15: Login-Service
    private static final short LOGIN_SERVICE = 15;

    // Type 16: Login-TCP-Port
    private static final short LOGIN_TCP_PORT = 16;

    // Type 18: Reply-Message
    private static final short REPLY_MESSAGE = 18;

    // Type 19: Callback-Number
    private static final short CALLBACK_NUMBER = 19;

    // Type 20: Callback-Id
    private static final short CALLBACK_ID = 20;

    // Type 22: Framed-Route
    private static final short FRAMED_ROUTE = 22;

    // Type 23: Framed-IPX-Network
    private static final short FRAMED_IPX_NETWORK = 23;

    // Type 24: State
    private static final short STATE = 24;

    // Type 25: Class
    private static final short CLASS = 25;

    // Type 26: Vendor-Specific
    private static final short VENDOR_SPECIFIC = 26;

    // Type 27: Session-Timeout
    private static final short SESSION_TIMEOUT = 27;

    // Type 28: Idle-Timeout
    private static final short IDLE_TIMEOUT = 28;

    // Type 29: Termination-Action
    private static final short TERMINATION_ACTION = 29;

    // Type 30: Called-Station-Id
    private static final short CALLED_STATION_ID = 30;

    // Type 31: Calling-Station-Id
    private static final short CALLING_STATION_ID = 31;

    // Type 32: NAS-Identifier
    private static final short NAS_IDENTIFIER = 32;

    // Type 33: Proxy-State
    private static final short PROXY_STATE = 33;

    // Type 34: Login-LAT-Service
    private static final short LOGIN_LAT_SERVICE = 34;

    // Type 35: Login-LAT-Node
    private static final short LOGIN_LAT_NODE = 35;

    // Type 36: Login-LAT-Group
    private static final short LOGIN_LAT_GROUP = 36;

    // Type 37: Framed-AppleTalk-Link
    private static final short FRAMED_APPLETALK_LINK = 37;

    // Type 38: Framed-AppleTalk-Network
    private static final short FRAMED_APPLETALK_NETWORK = 38;

    // Type 39: Framed-AppleTalk-Zone
    private static final short FRAMED_APPLETALK_ZONE = 39;

    // Type 60: CHAP-Challenge
    private static final short CHAP_CHALLENGE = 60;

    // Type 61: NAS-Port-Type
    private static final short NAS_PORT_TYPE = 61;

    // Type 62: Port-Limit
    private static final short PORT_LIMIT = 62;

    // Type 63: Login-LAT-Port
    private static final short LOGIN_LAT_PORT = 63;

    /**
     * Length field: It indicates the length of this attribute including the Type, Length and Value fields.
     * - 1 byte
     */
    private short length;

    /**
     * Value field: It contains information specific to the Attribute
     * - 0 or more bytes.
     * *NOTE: In this implementation, we only consider that this value follows 'string-1' format,
     * which is composed of maximum 253 octets composed of binary data
     */
    private byte[] value;

    // Constructor
    public Attribute(short type, short length, byte[] value) {
        this.type = type;
        this.length = length;
        this.value = value;
    }

    // Getters and setters
    public short getType() { return type; }
    public void setType(short type) {
        this.type = type;
    }

    public short getLength() {
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


}
