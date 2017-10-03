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

  public static String bString (byte[] data, int start) {
    for (int i = start; i < data.length; i++) {
      if (data [i] == 0) {  // found null termination
        if (i > start) {    // found a non-empty string
          return new String (data, start, i - start);
        } else {
          return new String ("");        /* empty string */
        }
      }
    }
    return null;
  }

  public static String[] bStringArray (byte[] data, int start, long count) {
      String[] result = new String[(int)count];
      int pos = start;
      for (int i = 0; i < count; i++) {
          result[i] = bString(data, pos);
          pos += result[i].length() + 1; 
      }
      return result;
  }

  // returns the next index after the null byte
  public static int wString (byte[] data, int start, String s) {
    byte[] sbytes = s.getBytes(charset);
    int length = sbytes.length;
// System.out.println("length for " + s + " is " + length + " in " + charset);
// System.out.println("data has length " + data.length + ", offset " + start);
    System.arraycopy(sbytes, 0, data, start, length);
    int endIndex = start + length;
    data [endIndex] = 0;   // null byte, to terminate the string
    return endIndex + 1;   // return the next index after the null byte
  }

  public static int numBytes (String s) {
    return s.getBytes(charset).length;
  }

  public static void debugPacket (boolean sent, byte[] data, int dlen,
                                   int code, String peer) {
    if (! debug)
      return;
    if (sent)
      System.out.print ("SocketUtils sending ");
    else
      System.out.print ("SocketUtils got ");
    System.out.println (dlen + " bytes, packet code " + code +
                        ", peer " + peer);
  }

  public static String sanitizeForHtml (String message) {
    java.util.regex.Pattern ltPat = java.util.regex.Pattern.compile ("<");
    java.util.regex.Matcher ltMat = ltPat.matcher (message);
    String noLt = ltMat.replaceAll ("&lt;");
    java.util.regex.Pattern gtPat = java.util.regex.Pattern.compile (">");
    java.util.regex.Matcher gtMat = ltPat.matcher (noLt);
    String noGt = gtMat.replaceAll ("&gt;");
    return noGt;
  }

}
