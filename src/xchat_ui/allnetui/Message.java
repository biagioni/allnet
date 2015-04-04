package allnetui;

/**
 *
 * @author Henry
 */
public class Message implements java.lang.Comparable<Message> {

    static final String SELF = "self";
    // the contact name of the sender
    final String from, to;
    final long sentTime;
    final long sequence;  // set to -1 if not known, e.g. for recv'd packets
    final String text;
    final boolean sentNotReceived;   // set to true if not known
    final boolean broadcast;  // only meaningful for received messages
    final String messageId;   // only meaningful for sent messages, may be null
    boolean isAcked;          // only meaningful for sent messages
    // set to false by the client when message has been read
    private boolean newMessgeFlag;  // only meaningful for received messages
    
//    Message(String from, String to, long sentTime, String text, boolean broadcast) {
//        this.from = from;
//        this.to = to;
//        this.sentTime = sentTime;
//        this.sequence = -1;
//        this.text = text;
//        this.broadcast = broadcast;
//        this.sentNotReceived = true;
//        this.messageId = null;
//        this.isAcked = false;
//        newMessgeFlag = false;
//    }
    
// use this for received messages only
    Message(String from, String to, long sentTime, String text,
            boolean broadcast, boolean newMessage) {
        this.from = from;
        this.to = to;
        this.sentTime = sentTime;
        this.sequence = -1;
        this.text = text;
        this.broadcast = broadcast;
        this.sentNotReceived = false;
        this.messageId = null;
        this.isAcked = false;
        newMessgeFlag = newMessage;
    }

    // sent messages should have a message ID, so we can figure out when they
    // are acked
    Message(String from, String to, long sentTime, long seq, String text,
            String messageId) {
        this.from = from;
        this.to = to;
        this.sentTime = sentTime;
        this.sequence = seq;
        this.text = text;
        this.sentNotReceived = true;
        this.broadcast = false;
        this.messageId = messageId;
        this.isAcked = false;
        newMessgeFlag = false;
    }

    boolean isNewMessage() {
        return newMessgeFlag;
    }

    void setRead() {
        newMessgeFlag = false;
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
      return ("message from " + from +
              ", to " + to +
              ", time " + sentTime +
              ", broadcast " + broadcast +
              ", text: '" + text + "'");
    }

    public boolean equals(Message m) {
        return m.sequence == sequence;
    }

    public int compareTo(Message m) {
      if (m == null)
        return 0;
      if ((this.sequence < 0) || (m.sequence < 0) ||
          (this.sentNotReceived != m.sentNotReceived)) { // compare by date
        if (this.sentTime < m.sentTime)
          return -1;
        else if (this.sentTime > m.sentTime)
          return 1;
        else 
          return 0;
      }
      if (this.sequence < m.sequence)
        return -1;
      else if (this.sequence > m.sequence)
        return 1;
      else 
        return 0;
    }

}
