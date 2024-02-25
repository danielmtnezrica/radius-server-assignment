package org.danielmartinez.radius;

import java.net.*;
import java.io.*;

/**
 * This class represents the RADIUS Server that follows the RFC 2865 guidelines
 */
public class RadiusServer {

    private final Integer RADIUS_PORT = 1812;
    private final Integer MTU = 1500;

    public static void main(String[] args) {
        RadiusServer radiusServer = new RadiusServer();
        radiusServer.start();
    }

    public void start(){
        try{
            DatagramSocket serverSocket = new DatagramSocket(RADIUS_PORT);
            System.out.println("RADIUS Server started. Listening on port " + serverSocket.getLocalPort());

            byte[] buffer = new byte[MTU];

            while(true){
                DatagramPacket receivePacket = new DatagramPacket(buffer, buffer.length);
                serverSocket.receive(receivePacket);

                System.out.println("Packet received from " + receivePacket.getAddress() + ":"
                        + receivePacket.getPort());
            }
        }
        catch(IOException e){
            System.out.println("IO: " + e.getMessage());
        }
    }

}