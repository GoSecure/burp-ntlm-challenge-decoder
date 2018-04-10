package burp.messages

import java.util.HashMap

abstract class SSPMessage(var raw: ByteArray) {
    var valid: Boolean = false
    var version: ByteArray? = null

    internal var output: MutableMap<String, String> = HashMap()

    override fun toString(): String {
        val buffer = StringBuilder()
        for (v in output.entries) {
            buffer.append(" - ${v.key}: ${v.value}\n")
        }
        buffer.append(" - Raw: ${raw.toHex()}")
        return buffer.toString()
    }

    fun ByteArray.toHex() = this.joinToString(separator = "") { it.toInt().and(0xff).toString(16).padStart(2, '0') }
}
