package burp;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class SSPChallenge extends SSPMessage {

    public SSPChallenge(byte[] SSPHeader) {
        super(SSPHeader);

        parseTarget(); // 8 bytes
        parseFlags(); // 4 bytes
        parseChallenge(); // 8 bytes
        parseTargetInfo(); // 8 bytes
    }


    private void parseTarget() {
        byte[] targetMessage = Arrays.copyOfRange(this.raw, 12, 20);

        short length = Utils.getShort(targetMessage, 0);
        short maxLength = Utils.getShort(targetMessage, 2);
        int offset = Utils.getInt(targetMessage, 4);

        this.output.put("Target", Utils.NTLMString(this.raw, length, maxLength, offset));
    }


    private void parseFlags() {
        byte[] flagMessage = Arrays.copyOfRange(this.raw, 20, 24);

        // reverse byte-order
        ByteBuffer bb = ByteBuffer.wrap(flagMessage);
        int flagsContainer = Integer.reverseBytes(bb.getInt());

        byte[] flags = ByteBuffer.allocate(4).putInt(flagsContainer).array();
    }


    private void parseChallenge() {
        byte[] flagMessage = Arrays.copyOfRange(this.raw, 24, 32);
        ByteBuffer bb = ByteBuffer.wrap(flagMessage);

        long challenge = Long.reverseBytes(bb.getLong());
    }

    private void parseTargetInfo() {
        byte[] targetInfoMessage = Arrays.copyOfRange(this.raw, 40, 48);
        //short type = Utils.getShort(targetInfoMessage, 0);
        short length = Utils.getShort(targetInfoMessage, 2);

        int offset = Utils.getInt(targetInfoMessage, 4);

        byte[] records = Arrays.copyOfRange(this.raw, offset, offset+length);

        int pos = 0;
        while ((pos + 4) < (records.length)) {
            short record_type = Utils.getShort(records, pos);
            short record_length = Utils.getShort(records, pos+2);

            pos += 4; // 2 x 2 bytes consumed

            //String test = Utils.NTLMString(records, record_length, record_length, pos);
            extractTargetInfoSubBlocks(records,record_type,record_length,pos);

            pos += record_length;

        }
    }

    private void extractTargetInfoSubBlocks(byte[] records, short type, short length, int pos) {
        // todo: clean this disgusting monster
        String blockName = "";
        String blockValue = "";
        if (type == 1) {
            blockName = "MsvAvNbComputerName";
            blockValue = Utils.NTLMString(records, length, length, pos);
        } else if (type == 2) {
            blockName = "MsvAvNbDomainName";
            blockValue = Utils.NTLMString(records, length, length, pos);
        } else if (type == 3) {
            blockName = "MsvAvDnsComputerName";
            blockValue = Utils.NTLMString(records, length, length, pos);
        } else if (type == 4) {
            blockName = "MsvAvDnsDomainName";
            blockValue = Utils.NTLMString(records, length, length, pos);
        } else if (type == 5) {
            blockName = "MsvAvDnsTreeName";
            blockValue = Utils.NTLMString(records, length, length, pos);
        } else if (type == 6) {
            blockName = "MsvAvFlags";
            blockValue = Utils.NTLMString(records, length, length, pos);
        } else if (type == 7) {
            blockName = "MsvAvTimestamp";

            // reverse byte-order
            byte[] timestampTmp = Arrays.copyOfRange(records, pos, pos+length);
            ByteBuffer bb = ByteBuffer.wrap(timestampTmp);
            long timestamp = Long.reverseBytes(bb.getLong());
            blockValue = Utils.win32FILETIMEtoDate(timestamp);
        } else if (type == 8) {
            blockName = "MsvAvSingleHost";
            blockValue = Utils.NTLMString(records, length, length, pos);
        } else if (type == 9) {
            blockName = "MsvAvTargetName";
            blockValue = Utils.NTLMString(records, length, length, pos);
        } else {
            blockName = "ERROR";
        }

        this.output.put(blockName, blockValue);
        //System.out.println(blockName + " : " + blockValue);
    }

    public String toString() {
        return("SSP Challenge message");
    }
}
