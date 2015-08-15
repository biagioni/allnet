package allnetui;

import java.util.HashMap;
import java.util.Iterator;

/**
 * Class to hold the client's data: contacts, keys, conversations.
 * 
 * The data can be modified by class UIController through calls to its public API. 
 * 
 * 
 * @author Henry
 */
class ClientData {
    private enum contactType { PERSONAL, BROADCAST };

    private String mySecretString;
    private HashMap<String, contactType> contactTypes;
    private HashMap<String, Conversation> conversations;

    ClientData() {
        contactTypes = new HashMap<>();
        conversations = new HashMap<>();
    }

    void createContact(String contactName, boolean isBroadcast) {
        if (contactExists(contactName)) {
            // throw new RuntimeException("tried to create contact with existing contact name: " + contactName);
            return;
        }
        if (isBroadcast)
          contactTypes.put(contactName, contactType.BROADCAST);
        else
          contactTypes.put(contactName, contactType.PERSONAL);
        conversations.put(contactName, new Conversation(contactName));
    }

    void removeContact(String contactName) {
        contactTypes.remove(contactName);
        conversations.remove(contactName);
    }

    String getMySecretString() {
        return mySecretString;
    }

    void setMySecretString(String mySecretString) {
        this.mySecretString = mySecretString;
    }

    boolean contactExists(String contactName) {
        return (contactTypes.containsKey(contactName));
    }

    boolean isBroadcast(String contactName) {
        return (contactTypes.get(contactName) == contactType.BROADCAST);
    }

    Conversation getConversation(String contactName) {
        return (conversations.get(contactName));
    }

    // get an iterator to allow us to iterate through all contacts (contact names)
    Iterator<String> getContactIterator() {
        return (contactTypes.keySet().iterator());
    }

    int getNumContacts() {
        return (contactTypes.size());
    }

    int getTotalNewMsgs() {
        Iterator<String> it = getContactIterator();
        int count = 0;
        Conversation conv;
        while (it.hasNext()) {
            conv = getConversation(it.next());
            count += conv.getNumNewMsgs();
        }
        return (count);
    }

    int getNumContactsWithNewMsgs() {
        Iterator<String> it = getContactIterator();
        int count = 0;
        Conversation conv;
        while (it.hasNext()) {
            conv = getConversation(it.next());
            if (conv.getNumNewMsgs() > 0)
                count++;
        }
        return (count);
    }

    int getNumNewMsgs(String contact) {
        Iterator<String> it = getContactIterator();
        int count = 0;
        Conversation conv;
        while (it.hasNext()) {
            conv = getConversation(it.next());
            if (conv.getNumNewMsgs() > 0)
                count++;
        }
        return (count);
    }
}
