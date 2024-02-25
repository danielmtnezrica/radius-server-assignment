package org.danielmartinez.radius;

import org.danielmartinez.radius.packet.RadiusPacket;
import org.danielmartinez.radius.packet.attribute.Attribute;

import java.net.*;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.danielmartinez.radius.constants.RadiusConstants;

/**
 * This class represents the RADIUS Server that follows the RFC 2865 guidelines
 */
public class RadiusServer {

    public static void main(String[] args) {
        RadiusServer radiusServer = new RadiusServer();
        radiusServer.start();
    }

    public void start(){
        try{
            DatagramSocket serverSocket = new DatagramSocket(RadiusConstants.RADIUS_LISTENING_PORT);
            System.out.println("RADIUS Server started. Listening on port " + serverSocket.getLocalPort());

            byte[] buffer = new byte[RadiusConstants.MAXIMUM_RADIUS_PACKET_LENGTH];

            while(true){
                DatagramPacket receivedUDPPacket = new DatagramPacket(buffer, buffer.length);
                serverSocket.receive(receivedUDPPacket);

                System.out.println("Packet received from " + receivedUDPPacket.getAddress() + ":"
                        + receivedUDPPacket.getPort());

                RadiusPacket receivedRadiusPacket = parseRadiusPacket(receivedUDPPacket);
                System.out.println(receivedRadiusPacket.toString());

                RadiusPacket responseRadiusPacket = processRadiusPacket(receivedRadiusPacket);
            }
        }
        catch(IOException e){
            System.out.println("IO: " + e.getMessage());
        }
    }

    /**
     * This method parses a UDP Packet Data that corresponds to a RADIUS Packet
     * @param packet: It contains the UDP Data in byte[] format
     * @return RadiusPacket: Byte fields in the UDP Data parsed to Java Data format
     */
    private RadiusPacket parseRadiusPacket(DatagramPacket packet){
        // Check packet length
        int packetLength = packet.getLength();
        if(packetLength < RadiusConstants.MINIMUM_RADIUS_PACKET_LENGTH || packetLength > RadiusConstants.MAXIMUM_RADIUS_PACKET_LENGTH){
            return null;
        }

        // Parse packet values
        byte[] radiusData = packet.getData();

        short radiusCode = radiusData[0];
        short radiusIdentifier = radiusData[1];
        int radiusLength = (((radiusData[2] & 0xFF) << 8) | (radiusData[3] & 0xFF));
        byte[] radiusAuthenticator = new byte[16];
        System.arraycopy(radiusData, 4, radiusAuthenticator, 0, 16);
        List<Attribute> radiusAttributes = parseRadiusPacketAttributes(radiusData, radiusLength);

        return new RadiusPacket(radiusCode, radiusIdentifier, radiusLength, radiusAuthenticator, radiusAttributes);
    }

    /**
     * This method parses the RADIUS Attributes field in a RADIUS Packet
     * @param radiusData : It contains the RADIUS Data in byte[] format
     * @param radiusLength: The length field in the RADIUS Packet
     * @return radiusAttributes: The Attributes field of a RADIUS Packet in List format
     */
    private List<Attribute> parseRadiusPacketAttributes(byte[] radiusData, int radiusLength){
        List<Attribute> radiusAttributes = new ArrayList<>();

        int radiusAttributeStartPosition = RadiusConstants.MINIMUM_RADIUS_PACKET_LENGTH;
        while (radiusAttributeStartPosition < radiusLength) {
            // Extract attribute type and length
            short attributeType = radiusData[radiusAttributeStartPosition];
            int attributeLength = radiusData[radiusAttributeStartPosition + 1];

            // Extract attribute value
            byte[] attributeValue = new byte[attributeLength];
            System.arraycopy(radiusData, radiusAttributeStartPosition, attributeValue, 0, attributeLength);

            // Add attribute to the attributes list
            Attribute attribute = new Attribute(attributeType, attributeLength, attributeValue);
            radiusAttributes.add(attribute);

            // Move to the next attribute
            radiusAttributeStartPosition += attributeLength;
        }

        return radiusAttributes;
    }

    /**
     *
     * @param radiusPacket
     */
    private RadiusPacket processRadiusPacket(RadiusPacket radiusPacket){
        // Check RADIUS Packet Field
        if(radiusPacket.getLength() < RadiusConstants.MINIMUM_RADIUS_PACKET_LENGTH){
            System.out.println("Packet discarded. Reason: The RADIUS length field is too short: (" +
                    radiusPacket.getLength() + " bytes) < " + RadiusConstants.MINIMUM_RADIUS_PACKET_LENGTH);
            return null;
        }

        if(radiusPacket.getLength() > RadiusConstants.MAXIMUM_RADIUS_PACKET_LENGTH){
            System.out.println("Packet discarded. Reason: The RADIUS length field is too long: (" +
                    radiusPacket.getLength() + " bytes) > " + RadiusConstants.MAXIMUM_RADIUS_PACKET_LENGTH);
            return null;
        }

        // Check RADIUS Code Field
        if (radiusPacket.getCode() < 0 || radiusPacket.getCode() > 255){
            System.out.println("Packet discarded. Reason: The RADIUS code field is out of bounds: Code" +
                    radiusPacket.getLength());
            return null;
        }

        else{
            if (radiusPacket.getCode() == RadiusConstants.ACCESS_REQUEST_CODE){
                return processAccessRequest(radiusPacket);
            }

            else{
                System.out.println("Packet discarded. Reason: Unknown RADIUS code: " + radiusPacket.getCode());
                return null;
            }
        }
    }

    private RadiusPacket processAccessRequest(RadiusPacket radiusPacket){
        // Check RADIUS attributes
        List<Attribute> radiusPacketAttributes = radiusPacket.getAttributes();
        HashMap<String, byte[]> credentialsMap = new HashMap<>();

        for (Attribute attribute: radiusPacketAttributes){
            if(attribute.getType() == RadiusConstants.USER_NAME){
                credentialsMap.put("USER_NAME", attribute.getValue());

            }
            else if(attribute.getType() == RadiusConstants.USER_PASSWORD){
                credentialsMap.put("USER_PASSWORD", attribute.getValue());
            }
        }

        if(credentialsMap.containsKey("USER_PASSWORD")){
            if(credentialsMap.containsKey("USER_NAME")){
                // Get SharedSecret
                // Get Request Authenticator
                // Get User Password
                // Authenticate
                System.out.println("Proceed to Authenticate: USER_PASSWORD and USER_NAME provided");
            }

            else{
                // Send Access-Reject
                System.out.println("Access-Reject. Reason: USER_NAME SHOULD be specified");
            }
        }

        else{
            // Send Access-Reject
            System.out.println("Access-Reject. Reason: USER_PASSWORD MUST be specified");
        }

        return null;
    }
}