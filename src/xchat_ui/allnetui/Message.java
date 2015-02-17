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
    final long sequence;  // set to -1 if not known
    final String text;
    final boolean broadcast;
    final boolean sentNotReceived;   // set to true if not known
    // set to false by the client when message has been read
    private boolean newMessgeFlag;
    
    Message(String from, String to, long sentTime, String text, boolean broadcast) {
        this.from = from;
        this.to = to;
        this.sentTime = sentTime;
        this.sequence = -1;
        this.text = text;
        this.broadcast = broadcast;
        this.sentNotReceived = true;
        newMessgeFlag = true;
    }
    
    Message(String from, String to, long sentTime, long seq, String text,
            boolean broadcast, boolean newMessage, boolean sentNotReceived) {
        this.from = from;
        this.to = to;
        this.sentTime = sentTime;
        this.sequence = seq;
        this.text = text;
        this.broadcast = broadcast;
        this.sentNotReceived = sentNotReceived;
        newMessgeFlag = newMessage;
    }

    boolean isNewMessage() {
        return newMessgeFlag;
    }

    void setRead() {
        newMessgeFlag = false;
    }

    @Override
    public String toString() {
      return ("message from " + from +
              ", to " + to +
              ", time " + sentTime +
              ", broadcast " + broadcast +
              ", text: '" + text + "'");
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
