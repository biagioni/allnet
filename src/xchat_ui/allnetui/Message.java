package allnetui;

/**
 *
 * @author Henry
 */
public class Message implements java.lang.Comparable<Message> {

    static final String SELF = "self";

    // a message is either sent or received
    boolean received;
    // the contact name of the sender
    final String from, to;
    final long sentTime;
    final long receivedTime;  // only meaningful for received packets
    final long sequence;  // set to -1 if not known, e.g. for recv'd packets
    final String text;
    final boolean sentNotReceived;   // set to true if not known
    final boolean broadcast;  // only meaningful for received messages
    final String messageId;   // only meaningful for sent messages, may be null
    boolean isAcked;          // only meaningful for sent messages
    // set to false by the client when message has been read
    boolean newMessageFlag;  // only meaningful for received messages
    
// use this for received messages only
    Message(String from, String to, long sentTime, long receivedTime, long seq,
            String text, boolean broadcast, boolean newMessage) {
        this.received = true;
        this.from = from;
        this.to = to;
        this.sentTime = sentTime;
        this.receivedTime = receivedTime;
        this.sequence = seq;
        this.text = text;
        this.broadcast = broadcast;
        this.sentNotReceived = false;
        this.messageId = null;
        this.isAcked = false;
        this.newMessageFlag = newMessage;
    }

    // sent messages should have a message ID, so we can figure out when they
    // are acked
    Message(String from, String to, long sentTime, long seq, String text,
            String messageId) {
        this.received = false;
        this.from = from;
        this.to = to;
        this.sentTime = sentTime;
        this.receivedTime = sentTime;
        this.sequence = seq;
        this.text = text;
        this.sentNotReceived = true;
        this.broadcast = false;
        this.messageId = messageId;
        this.isAcked = false;
        this.newMessageFlag = false;
    }

    boolean isReceivedMessage() {
        return this.received;
    }

    boolean isNewMessage() {
        return newMessageFlag;
    }

    void setRead() {
        newMessageFlag = false;
    }

    boolean isBroadcast() {
        return broadcast;
    }

    boolean acked() {
        return isAcked;
    }

    void setAcked(String ack) {
        if ((! isAcked) && (messageId != null) && (ack.equals(messageId)))
            isAcked = true;
    }

    boolean setAcked(long ack) {
        if (ack == sequence) {
            isAcked = true;
            return true;
        }
        return false;
    }

    @Override
    public String toString() {
      String isNew = (newMessageFlag ? ", new" : ", not new");
      return ("message from " + from +
              ", to " + to +
              ", time " + sentTime +
              ", broadcast " + broadcast + isNew +
              ", text: '" + text + "'");
    }

    public boolean equals(Message m) {
        return m.sequence == sequence;
    }

    public int compareTo(Message m) {
      if (m == null)
        return 0;   // unknown
      // originally had this comparison, which is useful to show messages
      // in sequence order.  However, if we later send
      // a message with an earlier sequence number, it sorts to be
      // earlier than sent messages with later sequence numbers,
      // but later than messages received earlier.  This causes an
      // inconsistent sort, with Java gets unhappy about
      // (and throws an exception which is mighty hard to debug)
      // discovered during a bug when I was sending everything with seq 1
//      if ((this.sentNotReceived == m.sentNotReceived) &&
//          (this.sequence >= 0) && (m.sequence >= 0)) { // compare seq numbers
//          if (this.sequence < m.sequence)
//            return -1;
//          else if (this.sequence > m.sequence)
//            return 1;
//      }   // just compare times and dates
      if (this.sentTime < m.sentTime)
          return -1;
      else if (this.sentTime > m.sentTime)
          return 1;
      return 0;  // equal
    }

    // always returns false if file time is null
    public boolean newer(java.nio.file.attribute.FileTime t) {
        if (t == null)
            return false;
        long ft = t.toMillis();
// System.out.println ("Message.java/newer: comparing " + ft + " to " + receivedTime);
        return ft <= this.receivedTime;
    }

    // only meaningful for received packets
    public long receivedAt() {
        return this.receivedTime;
    }

    public long sequence() {
        return this.sequence;
    }

}
