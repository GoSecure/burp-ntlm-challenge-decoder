package burp;

public class SSPResponse extends SSPMessage {

    public SSPResponse(byte[] SSPHeader) {
        super(SSPHeader);
    }

    public String toString() {
        return("SSP Response message");
    }
}
