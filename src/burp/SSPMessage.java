package burp;

import java.util.HashMap;
import java.util.Map;

public abstract class SSPMessage {
    boolean valid;
    byte[] raw;
    byte version[];

    Map<String,String> output = new HashMap<String,String>();

    public SSPMessage(byte[] SSPHeader) {
        this.raw = SSPHeader;
    }

    public abstract String toString();
}
