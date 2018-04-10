package burp.messages

import java.io.UnsupportedEncodingException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.Charset
import java.text.SimpleDateFormat
import java.util.*

object FormatUtils {

    val FILETIME_OFFSET = 11644473600L

    internal inline fun windowsVersion(majorVersion:Int, minorVersion:Int):String {
        //println("$majorVersion - $minorVersion")
        //Taken from "NT LAN Manager (NTLM) Authentication Protocol" page 86
        // https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/%5BMS-NLMP%5D.pdf
        if(majorVersion == 5 && minorVersion == 1) return "Windows XP Service Pack 2"
        if(majorVersion == 5 && minorVersion == 2) return "Windows Server 2003"
        if(majorVersion == 6 && minorVersion == 0) return "Windows Server 2008 / Windows Vista"
        if(majorVersion == 6 && minorVersion == 1) return "Windows Server 2008 R2 / Windows 7"
        if(majorVersion == 6 && minorVersion == 2) return "Windows Server 2012 / Windows 8"
        if(majorVersion == 6 && minorVersion == 3) return "Windows Server 2012 R2 / Windows 8.1"
        if(majorVersion == 10 && minorVersion == 0) return "Windows Server 2016 / Windows 10"

        //Fallback for unknown version
        if(majorVersion == 5) return "Windows Server 2003 / Windows XP (Unsure)"
        if(majorVersion == 6) return "Windows Server 2012 R2 / Windows 8.1"
        if(majorVersion == 10) return "Windows Server 2016 / Windows 10 (Unsure)"

        return "Version"
    }

    internal inline fun ntlmString(raw: ByteArray, length: Short, maxLength: Short, offset: Int): String {
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

    internal inline fun win32FILETIMEtoEpoch(filetime: Long): Long {
        return filetime / 10000000 - FILETIME_OFFSET
    }


    internal inline fun win32FILETIMEtoDate(filetime: Long): String {
        val epoch = filetime / 10000000 - FILETIME_OFFSET
        val date = Date(epoch * 1000)

        val formatter = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
        return formatter.format(date)
    }
}
