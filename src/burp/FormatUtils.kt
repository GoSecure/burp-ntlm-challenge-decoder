package burp

import java.io.UnsupportedEncodingException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.Charset
import java.text.SimpleDateFormat
import java.util.*

object FormatUtils {

    internal inline fun NTLMString(raw: ByteArray, length: Short, maxLength: Short, offset: Int): String {
        val target = String(raw, offset, length.toInt()).toCharArray()

        //dealing with UTF-16
        return if (target[1] == '\u0000') {
            try {
                String(raw, offset, length.toInt(), Charset.forName("UTF-16LE"))
            } catch (e: UnsupportedEncodingException) {
                target.toString()
            }

        } else {
            String(raw, offset, length.toInt())
        }
    }

    internal inline fun getShort(ba: ByteArray, offset: Int): Short {
        return ByteBuffer.wrap(ba, offset, 2)
                .order(ByteOrder.LITTLE_ENDIAN)
                .short
    }

    internal inline fun getInt(ba: ByteArray, offset: Int): Int {
        return ByteBuffer.wrap(ba, offset, 4)
                .order(ByteOrder.LITTLE_ENDIAN)
                .int
    }

    internal inline fun win32FILETIMEtoEpoch(FILETIME: Long?): Long {
        val FILETIME_OFFSET = 11644473600L
        return FILETIME!! / 10000000 - FILETIME_OFFSET
    }


    internal inline fun win32FILETIMEtoDate(FILETIME: Long?): String {
        val FILETIME_OFFSET = 11644473600L
        val epoch = FILETIME!! / 10000000 - FILETIME_OFFSET
        val date = Date(epoch * 1000)

        val formatter = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
        return formatter.format(date)
    }
}
