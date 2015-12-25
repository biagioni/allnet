package allnetui;

import java.net.*;

/**
 *
 * @author Edoardo Biagioni, esb@hawaii.edu
 *
 * A thread to read messages from xchat_socket and give them to the
 * user interface.  This class also maintains the socket and a buffer
 * (packet) used to send messages back to xchat_socket.
 */

public class XchatSocket extends Thread {

  // set to true to debug communications with xchat_socket.c
  static final boolean debug = false;

  static final DatagramSocket socket = initSocket();
  static final InetAddress local = InetAddress.getLoopbackAddress();
  UIAPI api = null;
  static final int xchatSocketPort = 0xa11c;  // ALLnet Chat port
  static final int allnetMTU = 12288;

  static final int codeDataMessage = 0;
  static final int codeBroadcastMessage = 1;
  static final int codeNewContact = 2;
  static final int codeAhra = 3;
  static final int codeSeq = 4;
  static final int codeAck = 5;
  static final int codeTrace = 6;
  static final int codeTraceReply = 7;
  static final java.nio.charset.Charset charset =
                   java.nio.charset.Charset.forName("UTF-8");

  static java.util.concurrent.LinkedBlockingQueue<Long> seqQueue =
    new java.util.concurrent.LinkedBlockingQueue<Long>();

  private static DatagramSocket initSocket() {
    try {
      return new DatagramSocket ();
    } catch (SocketException e) {
      System.out.println ("unable to open socket: " + e);
      System.exit (1);
    }
    return null;
  }

  // constructor.  Initialize the API variable
  public XchatSocket(UIAPI controller) {
    super();    // initialize thread
    this.api = controller;
  }

  // accessor methods
  public static DatagramSocket getSocket() {
    return socket;
  }

  public DatagramPacket makePacket(byte[] buf, int length) {
    DatagramPacket packet =
      new DatagramPacket (buf, length, local, xchatSocketPort);
    return packet;
  }

  private void sendInitial() {
    String s = new String("hello world\n");
    DatagramPacket p = makePacket(s.getBytes(), s.length());
    try {
      socket.send(p);
    } catch (java.io.IOException e) {
      System.out.println ("unable to send initial packet: " + e);
      System.exit (1);
    }
  }

  private static int b32 (byte [] data, int start, int len) {
    if (start + 4 > len)
      return 0;
    return (((((int) data [start    ]) & 0xff) << 24) |
            ((((int) data [start + 1]) & 0xff) << 16) |
            ((((int) data [start + 2]) & 0xff) <<  8) |
            ((((int) data [start + 3]) & 0xff)      ));
  }

  private static void w32 (byte [] data, int start, int value) {
    data [start  ] = ((byte) ((value >> 24) & 0xff));
    data [start+1] = ((byte) ((value >> 16) & 0xff));
    data [start+2] = ((byte) ((value >>  8) & 0xff));
    data [start+3] = ((byte) ((value      ) & 0xff));
  }

  private static long b48 (byte [] data, int start, int len) {
    if (start + 6 > len)
      return 0;
    return (((((long) data [start    ]) & 0xff) << 40) |
            ((((long) data [start + 1]) & 0xff) << 32) |
            ((((long) data [start + 2]) & 0xff) << 24) |
            ((((long) data [start + 3]) & 0xff) << 16) |
            ((((long) data [start + 4]) & 0xff) <<  8) |
            ((((long) data [start + 5]) & 0xff)      ));
  }

  private static void w48 (byte [] data, int start, long value) {
    data [start  ] = ((byte) ((value >> 40) & 0xff));
    data [start+1] = ((byte) ((value >> 32) & 0xff));
    data [start+2] = ((byte) ((value >> 24) & 0xff));
    data [start+3] = ((byte) ((value >> 16) & 0xff));
    data [start+4] = ((byte) ((value >>  8) & 0xff));
    data [start+5] = ((byte) ((value      ) & 0xff));
  }

  private static long b64 (byte [] data, int start, int len) {
    if (start + 8 > len)
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

  private static void w64 (byte [] data, int start, long value) {
    data [start  ] = ((byte) ((value >> 56) & 0xff));
    data [start+1] = ((byte) ((value >> 48) & 0xff));
    data [start+2] = ((byte) ((value >> 40) & 0xff));
    data [start+3] = ((byte) ((value >> 32) & 0xff));
    data [start+4] = ((byte) ((value >> 24) & 0xff));
    data [start+5] = ((byte) ((value >> 16) & 0xff));
    data [start+6] = ((byte) ((value >>  8) & 0xff));
    data [start+7] = ((byte) ((value      ) & 0xff));
  }

  private static class IntRef {
    int value;
  }

  private static class LongRef {
    long value;
  }

  private static String bString (byte [] data, int start, int len,
                                 IntRef nextIndex) {
    if (nextIndex == null)
      nextIndex = new IntRef();   // not used, but simplifies the code
    for (int i = start; i < len; i++) {
      if (data [i] == 0) {
        if (i > start) {
          nextIndex.value = i + 1;
          return new String (data, start, i - start);
        } else {
          nextIndex.value = start + 1;   /* skip this null character */
          return new String ("");        /* empty string */
        }
      }
    }
    nextIndex.value = len;               /* reached the end, no null char */
    return null;
  }

  private static int wString (byte [] data, int start, String s) {
    byte [] sbytes = s.getBytes(charset);
    int length = sbytes.length;
// System.out.println("length for " + s + " is " + length + " in " + charset);
    System.arraycopy(sbytes, 0, data, start, length);
    int endIndex = start + length;
    data [endIndex] = 0;   // null byte, to terminate the string
    return endIndex + 1;   // return the next index after the null byte
  }

  private static void debugPacket (boolean sent, byte [] data, int dlen,
                                   int code, String peer) {
    if (! debug)
      return;
    if (sent)
      System.out.print ("XchatSocket sending ");
    else
      System.out.print ("XchatSocket got ");
    System.out.println (dlen + " bytes, packet code " + code +
                        ", peer " + peer);
  }

  private static void debugOutgoing (DatagramPacket packet, int code,
                                     String peer) {
    debugPacket (true, packet.getData (), packet.getLength (), code, peer);
  }

  /* Decode a message (if possible), and call the corresponding API function.
   * messages have a length, time, code, peer name, and text
   *   length (4 bytes, big-endian order) includes everything.
   *   time (6 bytes, big-endian order) is the time of original transmission
   *   code is 1 byte, value 0 for a data message, 1 for broadcast,
   *     2 for key exchange (key exchanges don't have the message)
   *     3 for secrets
   *   the peer name and the message are null-terminated
   */
  private void decodeForwardPacket (byte [] data, int dlen) {
    if (dlen < 11)
      return;
    int length = b32 (data, 0, dlen);
    if (length != dlen) {
      System.out.println ("embedded length " + length + ", received " + dlen);
      /* return; */
    }
    long time = b48 (data, 4, dlen);
    int code = data [10];
    IntRef nextIndex = new IntRef();
    String peer = bString (data, 11, dlen, nextIndex);
    debugPacket (false, data, dlen, code, peer);
    if ((code == codeDataMessage) || (code == codeBroadcastMessage)) {
      String message = bString (data, nextIndex.value, dlen, nextIndex);
      // System.out.println ("message '" + message + "' from " + peer);
      boolean broadcastReceived = (code == 1);
      if (broadcastReceived)
        time = System.currentTimeMillis();
      else
        time *= 1000;  // convert seconds to milliseconds
      api.messageReceived (peer, time, message, broadcastReceived);
    } else if (code == codeNewContact) {
      System.out.println ("new key from " + peer);
      api.contactCreated(peer);
    } else if (code == codeAhra) {
      System.out.println ("subscription complete from " + peer);
      api.contactCreated(peer, true);
    } else if (code == codeSeq) {
      long seq = b64 (data, nextIndex.value, dlen);
      // System.out.println ("message to " + peer + " has sequence " + seq);
      try {
        seqQueue.put (seq);
      } catch (java.lang.InterruptedException e) {
        System.out.println ("sequence put exception: " + e);
      }
    } else if (code == codeAck) {
      long ack = b64 (data, nextIndex.value, dlen);
      // System.out.println ("from " + peer + " got ack " + ack);
      api.messageAcked (peer, ack);
    } else if (code == codeTraceReply) {
      String message = bString (data, nextIndex.value, dlen, nextIndex);
      System.out.println ("trace response '" + message + "'");
      api.traceReceived (message);
    } else {
      System.out.println ("unknown code " + code);
    }
  }

  private static DatagramPacket makeMessagePacket(String peer, String text,
                                                  LongRef time, boolean bc) {
    int size = peer.length() + text.getBytes(charset).length + 2 + 11;
    byte [] buf = new byte [size];
    DatagramPacket packet =
      new DatagramPacket (buf, size, local, xchatSocketPort);
    w32(buf, 0, size);
    time.value = System.currentTimeMillis();
    w48(buf, 4, time.value / 1000);
    if (bc)
      buf [10] = codeBroadcastMessage;
    else
      buf [10] = codeDataMessage;
    int newIndex = wString (buf, 11, peer);
    wString (buf, newIndex, text);
    return packet;
  }

  private static DatagramPacket makeKeyPacket(String peer, String s1,
                                              String s2, int hops) {
    int size = peer.length() + s1.getBytes(charset).length + 2 + 11;
    if ((s2 != null) && (s2.getBytes(charset).length > 0))
      size += s2.getBytes(charset).length + 1;
    byte [] buf = new byte [size];
    DatagramPacket packet =
      new DatagramPacket (buf, size, local, xchatSocketPort);
    w32(buf, 0, size);
    w48(buf, 4, hops);
    buf [10] = codeNewContact;
    int newIndex = wString(buf, 11, peer);
    newIndex = wString(buf, newIndex, s1);
    if ((s2 != null) && (s2.getBytes().length > 0))
      wString(buf, newIndex, s2);
    return packet;
  }

  private static DatagramPacket makeSubPacket(String ahra) {
    int size = ahra.getBytes().length + 1 + 11;
    byte [] buf = new byte [size];
    DatagramPacket packet =
      new DatagramPacket (buf, size, local, xchatSocketPort);
    w32(buf, 0, size);
    w48(buf, 4, 0);
    buf [10] = codeAhra;
    wString(buf, 11, ahra);
    return packet;
  }

  private static DatagramPacket makeTracePacket(int hops) {
    int size = 1 + 11;
    byte [] buf = new byte [size];
    DatagramPacket packet =
      new DatagramPacket (buf, size, local, xchatSocketPort);
    w32(buf, 0, size);
    w48(buf, 4, 0);
    buf [10] = codeTrace;
    buf [11] = (byte) hops;
    return packet;
  }

  private static boolean sendPacket(DatagramPacket packet) {
    try {
      socket.send (packet);
    } catch (java.io.IOException e) {
      System.out.println ("send exception: " + e);
      return false;
    }
    return true;
  }

  public static long sendToPeer(String peer, String text) {
    LongRef time = new LongRef();
    DatagramPacket packet = makeMessagePacket(peer, text, time, false);
    debugOutgoing (packet, codeDataMessage, peer);
    if (! sendPacket (packet)) {
      return -1;
    }
    try {
      return seqQueue.take (); // return the sequence number from xchat_socket
    } catch (java.lang.InterruptedException e) {
      System.out.println ("sequence take exception: " + e);
    }
    return -1;
  }

  public static boolean sendKeyRequest(String peer, String s1, String s2,
                                       int hops) {
    DatagramPacket packet = makeKeyPacket(peer, s1, s2, hops);
    debugOutgoing (packet, codeNewContact, peer);
    return sendPacket(packet);
  }

  public static boolean sendSubscription(String peer) {
    DatagramPacket packet = makeSubPacket(peer);
    debugOutgoing (packet, codeAhra, peer);
    return sendPacket(packet);
  }

  // start a trace with the given number of hops
  public static boolean sendTrace(int hops) {
System.out.println ("send_trace (" + hops + ")");
    DatagramPacket packet = makeTracePacket(hops);
    debugOutgoing (packet, codeTrace, "trace");
    return sendPacket(packet);
  }

  /* main method, called to start the thread
   * listen to the xchat socket for incoming messages.  Decode them,
   * and call the corresponding API function.
   */

  public void run() {
//    System.out.println("running XchatSocket.java");
    sendInitial();
    byte [] input = new byte [allnetMTU];
    DatagramPacket received = new DatagramPacket (input, input.length);
    while (true) {
      try {
        socket.receive (received);
      } catch (java.io.IOException e) {
        System.out.println ("receive got an exception: " + e);
        System.out.println ("unable to receive messages, terminating");
        System.exit (1);
      }
//      System.out.println ("received packet: " + received +
//                          " from " + received.getSocketAddress ());
      if (received.getPort () != xchatSocketPort) {
        System.out.println ("packet from port " + received.getPort() +
                            ", only accepting from " + xchatSocketPort);
      } else if (! received.getAddress().isLoopbackAddress()) {
        System.out.println ("packet from address " + received.getAddress() +
                            ", only accepting from loopback address" );
      } else {
        decodeForwardPacket (received.getData (), received.getLength ());
      }
    }
  }

}
