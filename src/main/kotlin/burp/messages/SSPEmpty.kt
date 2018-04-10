package burp.messages

/**
 * Null Object pattern. This class is used when the header can't be parsed.
 */
class SSPEmpty(sspHeader: ByteArray) : SSPMessage(sspHeader) {

    override fun toString(): String {
        return "Unable to load the message"
    }
}
