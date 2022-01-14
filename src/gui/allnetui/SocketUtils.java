  package allnetui;
  
  import java.net.*;
  
  /**
   *
   * @author Edoardo Biagioni, esb@hawaii.edu
   *
   * static methods that are useful in dealing with sockets
   */
  
  public class SocketUtils {
  
    static final java.nio.charset.Charset charset =
                     java.nio.charset.Charset.forName("UTF-8");
    static final boolean debug = false;
  
    public static int b32 (byte[] data, int start) {
      if (start + 4 > data.length)
        return 0;
      return (((((int) data [start    ]) & 0xff) << 24) |
              ((((int) data [start + 1]) & 0xff) << 16) |
              ((((int) data [start + 2]) & 0xff) <<  8) |
              ((((int) data [start + 3]) & 0xff)      ));
    }
  
    public static void w32 (byte[] data, int start, int value) {
      if (start + 4 > data.length)
        return;
      data [start  ] = ((byte) ((value >> 24) & 0xff));
      data [start+1] = ((byte) ((value >> 16) & 0xff));
      data [start+2] = ((byte) ((value >>  8) & 0xff));
      data [start+3] = ((byte) ((value      ) & 0xff));
    }
  
    public static long b48 (byte[] data, int start) {
      if (start + 6 > data.length)
        return 0;
      return (((((long) data [start    ]) & 0xff) << 40) |
              ((((long) data [start + 1]) & 0xff) << 32) |
              ((((long) data [start + 2]) & 0xff) << 24) |
              ((((long) data [start + 3]) & 0xff) << 16) |
              ((((long) data [start + 4]) & 0xff) <<  8) |
              ((((long) data [start + 5]) & 0xff)      ));
    }
  
    public static void w48 (byte[] data, int start, long value) {
      if (start + 6 > data.length)
        return;
      data [start  ] = ((byte) ((value >> 40) & 0xff));
      data [start+1] = ((byte) ((value >> 32) & 0xff));
      data [start+2] = ((byte) ((value >> 24) & 0xff));
      data [start+3] = ((byte) ((value >> 16) & 0xff));
      data [start+4] = ((byte) ((value >>  8) & 0xff));
      data [start+5] = ((byte) ((value      ) & 0xff));
    }
  
    public static long b64 (byte[] data, int start) {
      if (start + 8 > data.length)
        return 0;
      return (((((long) data [start    ]) & 0xff) << 56) |
              ((((long) data [start + 1]) & 0xff) << 48) |
              ((((long) data [start + 2]) & 0xff) << 40) |
              ((((long) data [start + 3]) & 0xff) << 32) |
              ((((long) data [start + 4]) & 0xff) << 24) |
              ((((long) data [start + 5]) & 0xff) << 16) |
              ((((long) data [start + 6]) & 0xff) <<  8) |
              ((((long) data [start + 7]) & 0xff)      ));
    }
  
    public static void w64 (byte[] data, int start, long value) {
      if (start + 8 > data.length)
        return;
      data [start  ] = ((byte) ((value >> 56) & 0xff));
      data [start+1] = ((byte) ((value >> 48) & 0xff));
      data [start+2] = ((byte) ((value >> 40) & 0xff));
      data [start+3] = ((byte) ((value >> 32) & 0xff));
      data [start+4] = ((byte) ((value >> 24) & 0xff));
      data [start+5] = ((byte) ((value >> 16) & 0xff));
      data [start+6] = ((byte) ((value >>  8) & 0xff));
      data [start+7] = ((byte) ((value      ) & 0xff));
    }
  
    public static boolean allZeros (byte[] data, int start) {
        if (start >= data.length)
            return false;
        for (int i = start; i < data.length; i++) {
            if (data[i] != 0)
                return false;
        }
        return true;
    }
  
    public static void setZeros (byte[] data, int start) {
        assert (start < data.length);
        for (int i = start; i < data.length; i++)
            data[i] = 0;
    }
  
    public static boolean sameTraceID (byte[] id1, byte[] id2) {
        if ((id1 == null) || (id2 == null) ||
            (id1.length != 16) || (id2.length != 16))
            return false;
        for (int i = 0; i < id1.length; i++) {
            if (id1[i] != id2[i])
                return false;
        }
        return true;
    }

    // returns the length of the string in bytes (NOT including the null char)
    // or -1 if no null char found 
    public static int bStringLength (byte[] data, int start) {
      for (int i = start; i < data.length; i++) {
        if (data [i] == 0) {  // found null termination
          return i - start;
        }
      }
      return -1;
    }
  
    public static String bString (byte[] data, int start, int length) {
      if (data [start + length] != 0) {   // should be the null char
        System.out.println ("data [" + start + " + " + length + "] == " +
                            data [start + length] + ", expected 0");
        return null;
      }
      if (length > 0) {
        return new String (data, start, length);
      } else {
        return new String ("");        /* empty string */
      }
    }
  
    // does not return the number of bytes consumed.  At least as of
    // 2022/01/13, all stringArrays are at the end of the message, so
    // should not matter, but if it ever does matter, must do something
    // similar to bStringLength
    public static String[] bStringArray (byte[] data, int start, long count) {
        String[] result = new String[(int)count];
        int pos = start;
        for (int i = 0; i < count; i++) {
            int length = bStringLength(data, pos);
            result[i] = bString(data, pos, length);
            if (result [i] == null) {
              System.out.println ("error copying string from data " + pos +
                                  "/" + data.length +
                                  ", string length " + length + 
                                  " but data [" + pos + " + " + length +
                                  " = " + (pos + length) + "] == " +
                                  data[pos + length] + ", 0 expected");
              result[i] = new String("");
              length = 0;
            }
            pos += length + 1; 
        }
        return result;
    }
  
    public static String hexNybble(byte b) {
        if ((b < 0) || (b > 15)) return "x";
        if (b < 10)              return "" + b;
        if (b == 10)             return "a";
        if (b == 11)             return "b";
        if (b == 12)             return "c";
        if (b == 13)             return "d";
        if (b == 14)             return "e";
                                 return "f";
    }

    public static String hexByte(byte b) {
        int i = (int)b;
        if (i < 0)
            i += 256;
        byte high = (byte)(i / 16);
        byte low = (byte)(i % 16);
        String result = hexNybble(high) + hexNybble(low);
if (result.length() > 2)
System.out.println("hex for " + b + "/" + i + " is " + result);
        return result;
    }
  
    public static void printBuffer(byte[] data, String message) {
        if (message != null)
            System.out.print(message + ": ");
        for (byte b: data) {
            System.out.print(hexByte(b) + " ");
        }
        System.out.println();
    }
  
    public static void printBuffer(byte[] data, int start, int max,
                                   String message) {
        if (message != null)
            System.out.print(message + ": ");
        System.out.print("(" + data.length + " bytes) ");
        for (int i = start; (i < start + max) && (i < data.length); i++) {
            System.out.print(hexByte(data[i]) + " ");
        }
        System.out.println();
    }

    private static long toJavaMilli(long sec) {
        return (sec + CoreConnect.allnetY2kSecondsInUnix) * 1000;
    }
  
    // message format is described in gui_respond.c/gui_send_result_messages
    // type/1, seq/8, missing/8, time_sent/8, timezone/2, time_receved/8,
    //   is_new/1 message/null-terminated
    public static Message[] bMessages (byte[] data, int start,
                                       long count, String contact, boolean bc) {
// printBuffer(data, "contact " + contact + ", count " + count + ", start " + start + ", bc " + bc);
// System.out.println("contact " + contact + ", count " + count + ", start " + start + ", bc " + bc + ", " + data.length + " bytes of data");
        Message[] result = new Message[(int)count];
        int pos = start;
long debugNow = java.time.Instant.now().getEpochSecond() * 1000;
        for (int i = 0; i < count; i++) {
// if (i + 10 > count) printBuffer(data, pos, 40, "contact " + contact + ", i " + i + "/" + count + ", pos " + pos + "/" + data.length);
            byte type = data[pos];  // 1 sent, 2 sent+acked, 3 received
            long seq = b64(data, pos + 1);
            long missing = b64(data, pos + 9);
            long sentTime = toJavaMilli(b64(data, pos + 17));
if (sentTime > debugNow) {
  System.out.println ("SocketUtils.java " + System.currentTimeMillis() +
                      ": contact " + contact +
                      ", strange sentTime " + sentTime +
                      ", expected less than " + debugNow);
}
            // we don't use timezone (and b16 is not defined)
            // int timezone = b16(data, pos + 25);
            long receivedTime = toJavaMilli(b64(data, pos + 27));
if (receivedTime > debugNow) {
  System.out.println ("SocketUtils.java: strange receivedTime " + receivedTime +
                      ", expected less than " + debugNow);
}
            boolean isNew = (data[pos + 35] != 0);
            int textLength = bStringLength(data, pos + 36);
            String text = bString(data, pos + 36, textLength);
            if (text == null) text = new String ("");
            if (type < 3) {          // sent message
                boolean acked = (type == 2);
                result[i] = new Message(contact, sentTime, seq, text, acked);
            } else {                 // received message
                result[i] = new Message(contact, sentTime, receivedTime,
                                        seq, text, bc, isNew, missing);
            }
            pos += 36 + textLength + 1;
        }
        return result;
    }

    // returns the C string (including the null byte) as a byte array
    public static byte[] wStringToBytes (String s) {
        byte[] sbytes = s.getBytes(charset);
        // Arrays.copyOf automatically puts 0 in the last byte, which
        // is the same as the C null termination
        return java.util.Arrays.copyOf(sbytes, sbytes.length + 1);
    }

    public static String makeFirstLineSmall (String message) {
        String eol = System.getProperty("line.separator");
        String[] lines = message.split(eol);
        if (lines.length > 0) {
            String first = "<small>" + lines[0] + "</small>";
            String rest = message.substring(lines[0].length());
            message = first + rest;
        }
        return message;
    }
  
}
