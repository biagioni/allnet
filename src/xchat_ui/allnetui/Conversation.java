package allnetui;

import java.util.ArrayList;
import java.util.Iterator;

/**
 * Class to hold a sequence of messages, and provide methods to track whether 
 * they have been read.
 * 
 * @author Henry
 */
public class Conversation {

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

    // add in the proper position
    // return true if added to the end, false if added earlier
    boolean add(Message message) {
        int length = messages.size();
        if ((length <= 0) ||
            (message.compareTo(messages.get(length - 1)) >= 0)) {
            messages.add(message);   // add at the end
            return true;
        } else {                     // insert before the end
            boolean added = false;
            for (int i = length - 2; i >= 0; i--) {
                if (message.compareTo(messages.get(i)) >= 0) {
                    messages.add(i + 1, message);   // add after this element
		    added = true;
// System.out.println ("added message at position " + (i + 1) + ", max " + length);
                    break;
                }
            }
            if (! added) {   // didn't find any message less than this one, so
                messages.add(0, message);   // add at the beginning
// System.out.println ("added message at start, max " + length);
            }
        }
        return false;
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
            messages.get(i).setRead();
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

    public ArrayList<Message> getMessages() {
        return messages;
    }

}
