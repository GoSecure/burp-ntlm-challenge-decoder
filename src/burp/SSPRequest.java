package burp;

public class SSPRequest extends SSPMessage {

    public SSPRequest(byte[] SSPHeader) {
        super(SSPHeader);
    }

    public String toString() {
        return("SSP Request message");
    }
}
