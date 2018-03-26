package burp.messages

import burp.FormatUtils
import java.nio.ByteBuffer
import java.util.*

class SSPChallenge(SSPHeader: ByteArray) : SSPMessage(SSPHeader) {

    init {
        parseTarget() // 8 bytes
        parseFlags() // 4 bytes
        parseChallenge() // 8 bytes
        parseTargetInfo() // 8 bytes
    }


    private fun parseTarget() {
        val targetMessage = Arrays.copyOfRange(this.raw, 12, 20)

        val length = FormatUtils.getShort(targetMessage, 0)
        val maxLength = FormatUtils.getShort(targetMessage, 2)
        val offset = FormatUtils.getInt(targetMessage, 4)

        this.output.put("Target", FormatUtils.ntlmString(this.raw, length, maxLength, offset))
    }


    private fun parseFlags() {
        val flagMessage = Arrays.copyOfRange(this.raw, 20, 24)

        // reverse byte-order
        val bb = ByteBuffer.wrap(flagMessage)
        val flagsContainer = Integer.reverseBytes(bb.int)

        val flags = ByteBuffer.allocate(4).putInt(flagsContainer).array()
    }


    private fun parseChallenge() {
        val flagMessage = Arrays.copyOfRange(this.raw, 24, 32)
        val bb = ByteBuffer.wrap(flagMessage)

        val challenge = java.lang.Long.reverseBytes(bb.long)
    }

    private fun parseTargetInfo() {
        val targetInfoMessage = Arrays.copyOfRange(this.raw, 40, 48)
        //short type = FormatUtils.getShort(targetInfoMessage, 0);
        val length = FormatUtils.getShort(targetInfoMessage, 2)

        val offset = FormatUtils.getInt(targetInfoMessage, 4)

        val records = Arrays.copyOfRange(this.raw, offset, offset + length)

        var pos = 0
        while (pos + 4 < records.size) {
            val recordType = FormatUtils.getShort(records, pos)
            val recordLength = FormatUtils.getShort(records, pos + 2)

            pos += 4 // 2 x 2 bytes consumed

            //String test = FormatUtils.ntlmString(records, record_length, record_length, pos);
            extractTargetInfoSubBlocks(records, recordType, recordLength, pos)

            pos += recordLength.toInt()

        }
    }

    private fun extractTargetInfoSubBlocks(records: ByteArray, type: Short, length: Short, pos: Int) {

        var blockName: String
        var blockValue = ""
        when (type.toInt()) {
            1 -> {
                blockName = "MsvAvNbComputerName"
                blockValue = FormatUtils.ntlmString(records, length, length, pos)
            }
            2 -> {
                blockName = "MsvAvNbDomainName"
                blockValue = FormatUtils.ntlmString(records, length, length, pos)
            }
            3 -> {
                blockName = "MsvAvDnsComputerName"
                blockValue = FormatUtils.ntlmString(records, length, length, pos)
            }
            4 -> {
                blockName = "MsvAvDnsDomainName"
                blockValue = FormatUtils.ntlmString(records, length, length, pos)
            }
            5 -> {
                blockName = "MsvAvDnsTreeName"
                blockValue = FormatUtils.ntlmString(records, length, length, pos)
            }
            6 -> {
                blockName = "MsvAvFlags"
                blockValue = FormatUtils.ntlmString(records, length, length, pos)
            }
            7 -> {
                blockName = "MsvAvTimestamp"

                // reverse byte-order
                val timestampTmp = Arrays.copyOfRange(records, pos, pos + length)
                val bb = ByteBuffer.wrap(timestampTmp)
                val timestamp = java.lang.Long.reverseBytes(bb.long)
                blockValue = FormatUtils.win32FILETIMEtoDate(timestamp)
            }
            8 -> {
                blockName = "MsvAvSingleHost"
                blockValue = FormatUtils.ntlmString(records, length, length, pos)
            }
            9 -> {
                blockName = "MsvAvTargetName"
                blockValue = FormatUtils.ntlmString(records, length, length, pos)
            }
            else -> {
                blockName = "ERROR"
            }
        }

        this.output.put(blockName, blockValue)
        //System.out.println(blockName + " : " + blockValue);
    }

    override fun toString(): String {
        return "SSP Challenge message"
    }
}
