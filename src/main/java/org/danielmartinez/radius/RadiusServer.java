package org.danielmartinez.radius;

import org.danielmartinez.radius.packet.RadiusPacket;
import org.danielmartinez.radius.packet.attribute.Attribute;

import java.net.*;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * This class represents the RADIUS Server that follows the RFC 2865 guidelines
 */
public class RadiusServer {

    private static final int RADIUS_LISTENING_PORT = 1812;
    private static final int MINIMUM_RADIUS_PACKET_LENGTH = 20;
    private static final int MAXIMUM_RADIUS_PACKET_LENGTH = 4096;

    public static void main(String[] args) {
        RadiusServer radiusServer = new RadiusServer();
        radiusServer.start();
    }

    public void start(){
        try{
            DatagramSocket serverSocket = new DatagramSocket(RADIUS_LISTENING_PORT);
            System.out.println("RADIUS Server started. Listening on port " + serverSocket.getLocalPort());

            byte[] buffer = new byte[MAXIMUM_RADIUS_PACKET_LENGTH];

            while(true){
                DatagramPacket receivePacket = new DatagramPacket(buffer, buffer.length);
                serverSocket.receive(receivePacket);

                System.out.println("Packet received from " + receivePacket.getAddress() + ":"
                        + receivePacket.getPort());

                RadiusPacket radiusPacket = parseRadiusPacket(receivePacket);
                System.out.println(radiusPacket.toString());
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
        if(packetLength < MINIMUM_RADIUS_PACKET_LENGTH || packetLength > MAXIMUM_RADIUS_PACKET_LENGTH){
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

        int radiusAttributeStartPosition = MINIMUM_RADIUS_PACKET_LENGTH;
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
    private void processRadiusPacket(RadiusPacket radiusPacket){
        // Check RADIUS Packet Field
        if(radiusPacket.getLength() < MINIMUM_RADIUS_PACKET_LENGTH){
            System.out.println("Packet discarded. Reason: The RADIUS packet field is too short: (" + radiusPacket.getLength() + " bytes) < " + MINIMUM_RADIUS_PACKET_LENGTH);
        }

        if(radiusPacket.getLength() > MAXIMUM_RADIUS_PACKET_LENGTH){
            System.out.println("Packet discarded. Reason: The RADIUS packet field is too long: (" + radiusPacket.getLength() + " bytes) > " + MAXIMUM_RADIUS_PACKET_LENGTH);
        }
    }
}