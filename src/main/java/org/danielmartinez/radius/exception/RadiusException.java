package org.danielmartinez.radius.exception;

/**
 * This class implements RADIUS related errors that can arise during the processing of a packet
 */
public class RadiusException extends RuntimeException{
    public RadiusException(String message) {
        super(message);
    }
}