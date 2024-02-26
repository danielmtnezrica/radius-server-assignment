package org.danielmartinez.radius.core;

import org.danielmartinez.radius.packet.RadiusPacket;
import org.danielmartinez.radius.packet.attribute.Attribute;

import java.net.*;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import org.danielmartinez.radius.constants.RadiusConstants;
import org.danielmartinez.radius.repository.UserManager;

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
                DatagramPacket receiveUDPPacket = new DatagramPacket(buffer, buffer.length);
                serverSocket.receive(receiveUDPPacket);

                System.out.println("Packet received from " + receiveUDPPacket.getAddress() + ":"
                        + receiveUDPPacket.getPort());

                // Parse the received UDP Packet
                RadiusPacket receiveRadiusPacket = parseUDPData(receiveUDPPacket.getData());
                System.out.println(receiveRadiusPacket.toString());

                // Process the Radius Packet accordingly
                RadiusPacket responseRadiusPacket = processRadiusPacket(receiveRadiusPacket);


                if(!Objects.isNull(responseRadiusPacket)){
                    System.out.println("Response: " + responseRadiusPacket.toString());
                    // Send response
                    InetAddress clientAddress = receiveUDPPacket.getAddress();
                    int clientPort = receiveUDPPacket.getPort();
                    byte[] responseData = responseRadiusPacket.toByteArray();
                    DatagramPacket responsePacket = new DatagramPacket(responseData, responseData.length, clientAddress, clientPort);
                    serverSocket.send(responsePacket);
                }
            }
        }
        catch(IOException e){
            System.out.println("IO: " + e.getMessage());
        }

        catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * This method parses a UDP Packet Data that corresponds to a RADIUS Packet
     * @param data: It contains the UDP Data in byte[] format
     * @return RadiusPacket: Byte fields in the UDP Data parsed to Java Data format
     */
    private RadiusPacket parseUDPData(byte[] data){
        // Check packet length
        int rawLength = data.length;
        if(rawLength < RadiusConstants.MINIMUM_RADIUS_PACKET_LENGTH || rawLength >
                RadiusConstants.MAXIMUM_RADIUS_PACKET_LENGTH){
            System.out.println("Packet discarded. Reason: The Packet length does not match the requirements");
            return null;
        }

        short radiusCode = data[0];
        short radiusIdentifier = data[1];
        int radiusLength = (((data[2] & 0xFF) << 8) | (data[3] & 0xFF));
        byte[] radiusAuthenticator = new byte[16];
        System.arraycopy(data, 4, radiusAuthenticator, 0, 16);
        List<Attribute> radiusAttributes = parseRadiusPacketAttributes(data, radiusLength);

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
            byte[] attributeValue = new byte[attributeLength - 2];
            System.arraycopy(radiusData, radiusAttributeStartPosition + 2, attributeValue, 0, attributeLength - 2);

            // Add attribute to the attributes list
            Attribute attribute = new Attribute(attributeType, attributeLength, attributeValue);
            radiusAttributes.add(attribute);

            // Move to the next attribute
            radiusAttributeStartPosition += attributeLength;
        }
        return radiusAttributes;
    }

    /**
     * This method processes a RADIUS packet and checks if it meets the requirements. Then, it determines
     * how to process the packet
     * @param radiusPacket: It contains the received RADIUS packet parsed
     * @return Null if the packet cannot be processed. The response RADIUS packet to the received RADIUS packet
     */
    private RadiusPacket processRadiusPacket(RadiusPacket radiusPacket){
        // Check RADIUS Length Field
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
                System.out.println("Packet discarded. Reason: Unknown RADIUS Code: " + radiusPacket.getCode());
                return null;
            }
        }
    }

    /**
     * This method processes a RADIUS Access-Request packet, checks if all conditions are met
     * and elaborates the appropiate response
     * @param radiusPacket RADIUS Access-Request received
     * @return An Access-Accept or an Access-Reject response
     */
    private RadiusPacket processAccessRequest(RadiusPacket radiusPacket){
        // Check RADIUS attributes
        List<Attribute> radiusPacketAttributes = radiusPacket.getAttributes();
        HashMap<String, byte[]> credentialsMap = new HashMap<>();
        UserManager userManager = new UserManager();

        for (Attribute attribute: radiusPacketAttributes){
            if(attribute.getType() == RadiusConstants.USER_NAME){
                credentialsMap.put("USER_NAME", attribute.getValue());

            }
            else if(attribute.getType() == RadiusConstants.USER_PASSWORD){
                credentialsMap.put("USER_PASSWORD", attribute.getValue());
            }
        }

        // Get SharedSecret
        if(userManager.clientExists("HARDCODED_CLIENTID")){
            credentialsMap.put("SHARED_SECRET", userManager.getSharedSecret("HARDCODED_CLIENTID"));
        }

        else{
            // Send Access-Reject
            System.out.println("Access-Reject. Reason: SHARED_SECRET does not exist for this client");

            RadiusPacket accessRejectPacket = new RadiusPacket(RadiusConstants.ACCESS_REJECT_CODE,
                    radiusPacket.getIdentifier(), radiusPacket.getAuthenticator());
            accessRejectPacket.setAttribute(RadiusConstants.REPLY_MESSAGE, 0,
                    RadiusConstants.ACCESS_REJECT_NO_SHARED_SECRET.getBytes());
            try{
                accessRejectPacket.setLength(accessRejectPacket.calculateLength());
                accessRejectPacket.setAuthenticatorResponse(radiusPacket, credentialsMap.get("SHARED_SECRET"),
                        accessRejectPacket.getAttributes());

                return accessRejectPacket;
            }

            catch (Exception e){
                e.printStackTrace();
                return null;
            }
        }

        if(credentialsMap.containsKey("USER_PASSWORD")){
            if(credentialsMap.containsKey("USER_NAME")){
                // Get Request Authenticator
                credentialsMap.put("REQUEST_AUTHENTICATOR", radiusPacket.getAuthenticator());

                // Authenticate
                System.out.println("Proceed to Authenticate: USER_PASSWORD and USER_NAME provided");
                boolean isUserAuthenticated = userManager.isUserAuthenticated(credentialsMap.get("USER_NAME"),
                        credentialsMap.get("USER_PASSWORD"), credentialsMap.get("REQUEST_AUTHENTICATOR"),
                        credentialsMap.get("SHARED_SECRET"));

                if(isUserAuthenticated){
                    System.out.println("User is authenticated");
                    // Send Access-Accept
                    RadiusPacket accessAcceptPacket = new RadiusPacket(RadiusConstants.ACCESS_ACCEPT_CODE,
                            radiusPacket.getIdentifier(), radiusPacket.getAuthenticator());
                    try{
                        accessAcceptPacket.setLength(accessAcceptPacket.calculateLength());
                        accessAcceptPacket.setAuthenticatorResponse(radiusPacket, credentialsMap.get("SHARED_SECRET"),
                                accessAcceptPacket.getAttributes());

                        return accessAcceptPacket;
                    }

                    catch (Exception e){
                        e.printStackTrace();
                        return null;
                    }
                }

                else{
                    // Send Access-Reject
                    System.out.println("Access-Reject. Reason: Wrong User Credentials");

                    RadiusPacket accessRejectPacket = new RadiusPacket(RadiusConstants.ACCESS_REJECT_CODE,
                            radiusPacket.getIdentifier(), radiusPacket.getAuthenticator());
                    try{
                        accessRejectPacket.setLength(accessRejectPacket.calculateLength());
                        accessRejectPacket.setAuthenticatorResponse(radiusPacket, credentialsMap.get("SHARED_SECRET"),
                                accessRejectPacket.getAttributes());

                        return accessRejectPacket;
                    }

                    catch (Exception e){
                        e.printStackTrace();
                        return null;
                    }
                }
            }

            else{
                // Send Access-Reject
                System.out.println("Access-Reject. Reason: USER_NAME SHOULD be specified");

                RadiusPacket accessRejectPacket = new RadiusPacket(RadiusConstants.ACCESS_REJECT_CODE,
                        radiusPacket.getIdentifier(), radiusPacket.getAuthenticator());

                try{
                    accessRejectPacket.setLength(accessRejectPacket.calculateLength());
                    accessRejectPacket.setAuthenticatorResponse(radiusPacket, credentialsMap.get("SHARED_SECRET"),
                            accessRejectPacket.getAttributes());

                    return accessRejectPacket;
                }

                catch (Exception e){
                    e.printStackTrace();
                    return null;
                }
            }
        }

        else{
            // Send Access-Reject
            System.out.println("Access-Reject. Reason: USER_PASSWORD MUST be specified");

            RadiusPacket accessRejectPacket = new RadiusPacket(RadiusConstants.ACCESS_REJECT_CODE,
                    radiusPacket.getIdentifier(), radiusPacket.getAuthenticator());

            try{
                accessRejectPacket.setLength(accessRejectPacket.calculateLength());
                accessRejectPacket.setAuthenticatorResponse(radiusPacket, credentialsMap.get("SHARED_SECRET"),
                        accessRejectPacket.getAttributes());

                return accessRejectPacket;
            }

            catch (Exception e){
                e.printStackTrace();
                return null;
            }
        }
    }
}