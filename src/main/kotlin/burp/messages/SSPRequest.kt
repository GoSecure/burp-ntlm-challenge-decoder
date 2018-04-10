package burp.messages

class SSPRequest(sspHeader: ByteArray) : SSPMessage(sspHeader) {

    override fun toString(): String {
        return "SSP Request message"
    }
}
