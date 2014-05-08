package allnetui;

/**
 *
 * @author Henry
 */
class Message {

    static final String SELF = "self";
    // the contact name of the sender
    final String from, to;
    final long sentTime;
    final String text;
    // set to false by the client when message has been read
    private boolean newMessgeFlag;
    
    Message(String from, String to, long sentTime, String text) {
        this.from = from;
        this.to = to;
        this.sentTime = sentTime;
        this.text = text;
        newMessgeFlag = true;
    }

    boolean isNewMessage() {
        return newMessgeFlag;
    }

    void setRead() {
        newMessgeFlag = false;
    }

    
        
}
