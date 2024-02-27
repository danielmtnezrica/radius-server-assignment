package org.danielmartinez.radius.util;

/**
 * Constants related to RADIUS protocol
 */
public class RadiusConstants {
    /**
     * RADIUS Code values
     */
    // Code 1: Access-Request
    public static final int ACCESS_REQUEST_CODE = 1;

    // Code 2: Access-Accept
    public static final int ACCESS_ACCEPT_CODE = 2;

    // Code 3: Access-Reject
    public static final int ACCESS_REJECT_CODE = 3;

    // Code 4: Accounting-Request
    public static final int ACCOUNTING_REQUEST_CODE = 4;

    // Code 5: Accounting-Response
    public static final int ACCOUNTING_RESPONSE_CODE = 5;

    // Code 11: Access-Challenge
    public static final int ACCESS_CHALLENGE_CODE = 11;

    // Code 12: Status-Server (experimental)
    public static final int STATUS_SERVER_CODE = 12;

    // Code 13: Status-Client (experimental)
    public static final int STATUS_CLIENT_CODE = 13;

    // Code 255: Reserved
    public static final int RESERVED_CODE = 255;

    /**
     * RADIUS Attribute-Type values
     */
    // Type 1: User-Name
    public static final int USER_NAME = 1;

    // Type 2: User-Password
    public static final int USER_PASSWORD = 2;

    // Type 3: CHAP-Password
    public static final int CHAP_PASSWORD = 3;

    // Type 4: NAS-IP-Address
    public static final int NAS_IP_ADDRESS = 4;

    // Type 5: NAS-Port
    public static final int NAS_PORT = 5;

    // Type 6: Service-Type
    public static final int SERVICE_TYPE = 6;

    // Type 7: Framed-Protocol
    public static final int FRAMED_PROTOCOL = 7;

    // Type 8: Framed-IP-Address
    public static final int FRAMED_IP_ADDRESS = 8;

    // Type 9: Framed-IP-Netmask
    public static final int FRAMED_IP_NETMASK = 9;

    // Type 10: Framed-Routing
    public static final int FRAMED_ROUTING = 10;

    // Type 11: Filter-Id
    public static final int FILTER_ID = 11;

    // Type 12: Framed-MTU
    public static final int FRAMED_MTU = 12;

    // Type 13: Framed-Compression
    public static final int FRAMED_COMPRESSION = 13;

    // Type 14: Login-IP-Host
    public static final int LOGIN_IP_HOST = 14;

    // Type 15: Login-Service
    public static final int LOGIN_SERVICE = 15;

    // Type 16: Login-TCP-Port
    public static final int LOGIN_TCP_PORT = 16;

    // Type 18: Reply-Message
    public static final int REPLY_MESSAGE = 18;

    // Type 19: Callback-Number
    public static final int CALLBACK_NUMBER = 19;

    // Type 20: Callback-Id
    public static final int CALLBACK_ID = 20;

    // Type 22: Framed-Route
    public static final int FRAMED_ROUTE = 22;

    // Type 23: Framed-IPX-Network
    public static final int FRAMED_IPX_NETWORK = 23;

    // Type 24: State
    public static final int STATE = 24;

    // Type 25: Class
    public static final int CLASS = 25;

    // Type 26: Vendor-Specific
    public static final int VENDOR_SPECIFIC = 26;

    // Type 27: Session-Timeout
    public static final int SESSION_TIMEOUT = 27;

    // Type 28: Idle-Timeout
    public static final int IDLE_TIMEOUT = 28;

    // Type 29: Termination-Action
    public static final int TERMINATION_ACTION = 29;

    // Type 30: Called-Station-Id
    public static final int CALLED_STATION_ID = 30;

    // Type 31: Calling-Station-Id
    public static final int CALLING_STATION_ID = 31;

    // Type 32: NAS-Identifier
    public static final int NAS_IDENTIFIER = 32;

    // Type 33: Proxy-State
    public static final int PROXY_STATE = 33;

    // Type 34: Login-LAT-Service
    public static final int LOGIN_LAT_SERVICE = 34;

    // Type 35: Login-LAT-Node
    public static final int LOGIN_LAT_NODE = 35;

    // Type 36: Login-LAT-Group
    public static final int LOGIN_LAT_GROUP = 36;

    // Type 37: Framed-AppleTalk-Link
    public static final int FRAMED_APPLETALK_LINK = 37;

    // Type 38: Framed-AppleTalk-Network
    public static final int FRAMED_APPLETALK_NETWORK = 38;

    // Type 39: Framed-AppleTalk-Zone
    public static final int FRAMED_APPLETALK_ZONE = 39;

    // Type 60: CHAP-Challenge
    public static final int CHAP_CHALLENGE = 60;

    // Type 61: NAS-Port-Type
    public static final int NAS_PORT_TYPE = 61;

    // Type 62: Port-Limit
    public static final int PORT_LIMIT = 62;

    // Type 63: Login-LAT-Port
    public static final int LOGIN_LAT_PORT = 63;

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
