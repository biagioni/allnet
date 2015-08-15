package allnetui;

import java.util.ArrayList;
import java.util.Iterator;

/**
 * Class to hold a sequence of messages, and provide methods to track whether 
 * they have been read.
 * 
 * @author Henry
 */
class Conversation {

    private static final long serialVersionUID = 1L;
    // list of messages in order received
    private ArrayList<Message> messages;
    // the other person in the conversation
    private String otherParty;

    Conversation(String otherParty) {
        this.otherParty = otherParty;
        messages = new ArrayList<>();
    }

    int getNumNewMsgs() {
        int count = 0;
        for (Message msg: messages)
            if (msg.isNewMessage())
                count++;
        return (count);
    }

    void add(Message message) {
        messages.add(message);
    }

    long getLastRxMessageTime() {
        Message msg = getLastRxMessage();
        if (msg != null) {
            return (msg.sentTime);
        }
        else {
            // no rx'd msgs yet
            return (0);
        }
    }

    void setReadAll() {
        Message msg;
        for (int i = messages.size() - 1; i >= 0; i--) {
            msg = messages.get(i);
            if (msg.from.equals(otherParty)) {
                if (!msg.isNewMessage()) {
                    return;
                }
                msg.setRead();
            }
        }
    }

    String getOtherParty() {
        return otherParty;
    }

    Message getLastRxMessage() {
        Message msg;
        for (int i = messages.size() - 1; i >= 0; i--) {
            msg = messages.get(i);
            if (msg.from.equals(otherParty)) {
                return (msg);
            }
        }
        // no rx'd msgs yet
        return (null);
    }

    boolean isEmpty() {
        return (messages.isEmpty());
    }

    void clear() {
        messages.clear();
    }

    Iterator<Message> getIterator() {
        return (messages.iterator());
    }
}
