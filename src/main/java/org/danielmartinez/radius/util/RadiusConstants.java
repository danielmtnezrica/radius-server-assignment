package org.danielmartinez.radius.util;

/**
 * Constants related to RADIUS protocol
 */
public class RadiusConstants {
    /**
     * RADIUS Code values
     */
    // Code 1: Access-Request
    public static final short ACCESS_REQUEST_CODE = 1;

    // Code 2: Access-Accept
    public static final short ACCESS_ACCEPT_CODE = 2;

    // Code 3: Access-Reject
    public static final short ACCESS_REJECT_CODE = 3;

    // Code 4: Accounting-Request
    public static final short ACCOUNTING_REQUEST_CODE = 4;

    // Code 5: Accounting-Response
    public static final short ACCOUNTING_RESPONSE_CODE = 5;

    // Code 11: Access-Challenge
    public static final short ACCESS_CHALLENGE_CODE = 11;

    // Code 12: Status-Server (experimental)
    public static final short STATUS_SERVER_CODE = 12;

    // Code 13: Status-Client (experimental)
    public static final short STATUS_CLIENT_CODE = 13;

    // Code 255: Reserved
    public static final short RESERVED_CODE = 255;

    /**
     * RADIUS Attribute-Type values
     */
    // Type 1: User-Name
    public static final short USER_NAME = 1;

    // Type 2: User-Password
    public static final short USER_PASSWORD = 2;

    // Type 3: CHAP-Password
    public static final short CHAP_PASSWORD = 3;

    // Type 4: NAS-IP-Address
    public static final short NAS_IP_ADDRESS = 4;

    // Type 5: NAS-Port
    public static final short NAS_PORT = 5;

    // Type 6: Service-Type
    public static final short SERVICE_TYPE = 6;

    // Type 7: Framed-Protocol
    public static final short FRAMED_PROTOCOL = 7;

    // Type 8: Framed-IP-Address
    public static final short FRAMED_IP_ADDRESS = 8;

    // Type 9: Framed-IP-Netmask
    public static final short FRAMED_IP_NETMASK = 9;

    // Type 10: Framed-Routing
    public static final short FRAMED_ROUTING = 10;

    // Type 11: Filter-Id
    public static final short FILTER_ID = 11;

    // Type 12: Framed-MTU
    public static final short FRAMED_MTU = 12;

    // Type 13: Framed-Compression
    public static final short FRAMED_COMPRESSION = 13;

    // Type 14: Login-IP-Host
    public static final short LOGIN_IP_HOST = 14;

    // Type 15: Login-Service
    public static final short LOGIN_SERVICE = 15;

    // Type 16: Login-TCP-Port
    public static final short LOGIN_TCP_PORT = 16;

    // Type 18: Reply-Message
    public static final short REPLY_MESSAGE = 18;

    // Type 19: Callback-Number
    public static final short CALLBACK_NUMBER = 19;

    // Type 20: Callback-Id
    public static final short CALLBACK_ID = 20;

    // Type 22: Framed-Route
    public static final short FRAMED_ROUTE = 22;

    // Type 23: Framed-IPX-Network
    public static final short FRAMED_IPX_NETWORK = 23;

    // Type 24: State
    public static final short STATE = 24;

    // Type 25: Class
    public static final short CLASS = 25;

    // Type 26: Vendor-Specific
    public static final short VENDOR_SPECIFIC = 26;

    // Type 27: Session-Timeout
    public static final short SESSION_TIMEOUT = 27;

    // Type 28: Idle-Timeout
    public static final short IDLE_TIMEOUT = 28;

    // Type 29: Termination-Action
    public static final short TERMINATION_ACTION = 29;

    // Type 30: Called-Station-Id
    public static final short CALLED_STATION_ID = 30;

    // Type 31: Calling-Station-Id
    public static final short CALLING_STATION_ID = 31;

    // Type 32: NAS-Identifier
    public static final short NAS_IDENTIFIER = 32;

    // Type 33: Proxy-State
    public static final short PROXY_STATE = 33;

    // Type 34: Login-LAT-Service
    public static final short LOGIN_LAT_SERVICE = 34;

    // Type 35: Login-LAT-Node
    public static final short LOGIN_LAT_NODE = 35;

    // Type 36: Login-LAT-Group
    public static final short LOGIN_LAT_GROUP = 36;

    // Type 37: Framed-AppleTalk-Link
    public static final short FRAMED_APPLETALK_LINK = 37;

    // Type 38: Framed-AppleTalk-Network
    public static final short FRAMED_APPLETALK_NETWORK = 38;

    // Type 39: Framed-AppleTalk-Zone
    public static final short FRAMED_APPLETALK_ZONE = 39;

    // Type 60: CHAP-Challenge
    public static final short CHAP_CHALLENGE = 60;

    // Type 61: NAS-Port-Type
    public static final short NAS_PORT_TYPE = 61;

    // Type 62: Port-Limit
    public static final short PORT_LIMIT = 62;

    // Type 63: Login-LAT-Port
    public static final short LOGIN_LAT_PORT = 63;

    /**
     * Access-Reject reasons
     */
    public static final String ACCESS_REJECT_NO_PASSWORD = "USER_PASSWORD MUST be specified";
    public static final String ACCESS_REJECT_BAD_CREDENTIALS = "Wrong User Credentials";
    public static final String ACCESS_REJECT_NO_USER_NAME = "USER_NAME SHOULD be specified";
    public static final String ACCESS_REJECT_NO_SHARED_SECRET = "SHARED_SECRET does not exist for this client";
    public static final String ACCESS_REJECT_UNKNOWN_USER_NAME = "Unknown USER_NAME";

    /**
     * Packet discarded reasons
     */
    public static final String PACKET_DISCARDED_PACKET_LENGTH = "The Packet length does not match the requirements";
    public static final String PACKET_DISCARDED_RADIUS_LENGTH_SHORT = "The RADIUS length field is too short";
    public static final String PACKET_DISCARDED_RADIUS_LENGTH_LONG = "The RADIUS length field is too long";
    public static final String PACKET_DISCARDED_RADIUS_CODE_WRONG = "The RADIUS code field is out of bounds";
    public static final String PACKET_DISCARDED_RADIUS_CODE_UNKNOWN = "The RADIUS code field is unknown";

    /**
     * Other constants
     */

    public static final int RADIUS_LISTENING_PORT = 1812;
    public static final int MINIMUM_RADIUS_PACKET_LENGTH = 20;
    public static final int MAXIMUM_RADIUS_PACKET_LENGTH = 4096;
}
