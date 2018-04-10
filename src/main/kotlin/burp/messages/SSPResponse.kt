package burp.messages

class SSPResponse(sspHeader: ByteArray) : SSPMessage(sspHeader) {

    override fun toString(): String {
        return "SSP Response message"
    }
}