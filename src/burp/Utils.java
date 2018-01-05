package burp;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

public class Utils {
    static String NTLMString(byte[] raw, short length, short maxLength, int offset) {
        char[] target = new String(raw, offset, length).toCharArray();

        //dealing with UTF-16
        if (target[1] == 0x00) {
            try{
                return new String(raw, offset, length, "UTF-16LE");
            } catch(UnsupportedEncodingException e) {
                return target.toString();
            }
        } else {
            return new String(raw, offset, length);
        }
    }

    static short getShort(byte[] ba, int offset) {
        return ByteBuffer.wrap(ba, offset, 2)
                .order(ByteOrder.LITTLE_ENDIAN)
                .getShort();
    }
    static int getInt(byte[] ba, int offset) {
        return ByteBuffer.wrap(ba, offset, 4)
                .order(ByteOrder.LITTLE_ENDIAN)
                .getInt();
    }

    static long win32FILETIMEtoEpoch(Long FILETIME) {
        Long FILETIME_OFFSET = 11644473600L;
        return (FILETIME / 10000000 - FILETIME_OFFSET);
    }

    static String win32FILETIMEtoDate(Long FILETIME) {
        Long FILETIME_OFFSET = 11644473600L;
        Long epoch = (FILETIME / 10000000 - FILETIME_OFFSET);
        Date date = new Date( epoch * 1000 );

        Format formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return formatter.format(date);
    }
}
