package burp;

import java.util.Arrays;

public class SSPMessageFactory {

    public static SSPMessage getMessage(byte[]  SSPHeader) {
        byte[] versionMessage = Arrays.copyOfRange(SSPHeader, 8, 12);

        int version = new Byte(versionMessage[0]).intValue();

        switch (version) {
            case 1:
                return new SSPRequest(SSPHeader);
            case 2:
                return new SSPChallenge(SSPHeader);
            case 3:
                return new SSPResponse(SSPHeader);
            default:
                return null;
        }
    }

}
