package burp.messages

import java.util.HashMap

abstract class SSPMessage(var raw: ByteArray) {
    var valid: Boolean = false
    var version: ByteArray? = null

    internal var output: MutableMap<String, String> = HashMap()

    abstract override fun toString(): String
}
