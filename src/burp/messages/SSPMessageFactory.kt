package burp.messages

import java.util.*

object SSPMessageFactory {

    fun getMessage(sspHeader: ByteArray): SSPMessage {
        val versionMessage = Arrays.copyOfRange(sspHeader, 8, 12)

        val version = versionMessage[0].toInt()

        when (version) {
            1 -> return SSPRequest(sspHeader)
            2 -> return SSPChallenge(sspHeader)
            3 -> return SSPResponse(sspHeader)
            else -> return SSPEmpty(sspHeader)
        }
    }

}