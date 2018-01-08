package burp.messages

import java.util.HashMap

abstract class SSPMessage(internal var raw: ByteArray) {
    internal var valid: Boolean = false
    internal var version: ByteArray? = null

    internal var output: MutableMap<String, String> = HashMap()

    abstract override fun toString(): String
}
