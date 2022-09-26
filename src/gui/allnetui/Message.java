
package allnetui;

/**
 *
 * @author Henry
 */
public class Message implements java.lang.Comparable<Message> {

    static final String SELF = "self-internal-unlikely-as-a-real-persons-name";

    // a message is either sent or received
    boolean received;
    // the contact name of the sender
    final String from, to;    // when sent/received, from/to may be SELF
    final long sentTime;
    final long receivedTime;  // only meaningful for received packets
    final long sequence;      // set to -1 if not known, e.g. for recv'd packets
    final String text;
    final boolean sentNotReceived;   // set to true if not known
    final boolean broadcast;  // only meaningful for received messages
    final long prevMissing;   // only meaningful for received messages
    boolean isAcked;          // only meaningful for sent messages
    // set to false by the client when message has been read
    boolean newMessageFlag;   // only meaningful for received messages
    
    // use this for received messages only
    Message(String from, long sentTime, long receivedTime, long seq,
            String text, boolean broadcast, boolean newMessage,
            long prevMissing) {
        this.received = true;
        this.from = from;
        this.to = SELF;
        this.sentTime = sentTime;
        this.receivedTime = receivedTime;
        this.sequence = seq;
        this.text = text;
        this.broadcast = broadcast;
        this.prevMissing = prevMissing;
        this.sentNotReceived = false;
        this.isAcked = false;
        this.newMessageFlag = newMessage;
    }

    // use this for sent messages
    Message(String to, long sentTime, long seq, String text, boolean isAcked) {
        this.received = false;
        this.from = SELF;
        this.to = to;
        this.sentTime = sentTime;
        this.receivedTime = sentTime;
        this.sequence = seq;
        this.text = text;
        this.sentNotReceived = true;
        this.broadcast = false;
        this.prevMissing = 0;
        this.isAcked = isAcked;
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

    boolean setAcked(long ack) {
        if ((ack == sequence) && (sentNotReceived)) {
            isAcked = true;
            return true;
        }
        return false;
    }

    @Override
    public String toString() {
      String isNew = (newMessageFlag ? ", new" : ", not new");
      String missing = ((prevMissing == 0) ? "" :
                        (", " + prevMissing + " messages missing before this"));
      return ("message from " + from +
              ", to " + to +
              ", seq " + sequence +
              ", time " + sentTime +
              ", broadcast " + broadcast + isNew + missing +
              ", text: '" + text + "'");
    }

    public boolean equals(Message m) {
        return ((m.sequence == sequence) &&
                (m.sentNotReceived == sentNotReceived));
    }

    // only use for sent messages
    public boolean sameMessageDifferentDestination(Message m) {
        return (sentNotReceived &&
                (sentNotReceived == m.sentNotReceived) &&
                (sentTime == m.sentTime) &&
                (text.equals(m.text)) &&
                (! to.equals(m.to)));
    }

    public int compareTo(Message m) {
      if (m == null)
        return 0;   // unknown
      // originally had this comparison, which is useful to show messages
      // in sequence order.  However, if we later send
      // a message with an earlier sequence number, it sorts to be
      // earlier than sent messages with later sequence numbers,
      // but later than messages received earlier.  This causes an
      // inconsistent sort, which Java gets unhappy about
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
      if (this.sentTime > m.sentTime)
          return 1;
      // times are the same, compare sequence numbers
      if ((this.sequence >= 0) && (m.sequence >= 0)) {
          if (this.sequence > m.sequence)
            return 1;
          if (this.sequence < m.sequence)
            return -1;
      }
      // times and sequence numbers are the same, the messages are the same
      return 0;  // equal
    }

    // only meaningful for received packets
    public long receivedAt() {
        return this.receivedTime;
    }

    public long sequence() {
        return this.sequence;
    }

    // returns null for a sent message
    public String receivedFrom() {
        if (received) {
            return this.from;
        }
        return null;
    }

    // returns null for a received message
    public String sentTo() {
        if (received) {
            return null;
        }
        return this.to;
    }

    // this is only the initial value -- it is NOT updated when
    // new messages come in
    public long prevMissing() {
        return this.prevMissing;
    }

}
