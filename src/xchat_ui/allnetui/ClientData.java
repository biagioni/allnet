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

    private String mySecretString;
    private HashMap<String, String> contactKeys;
    private HashMap<String, Conversation> conversations;

    ClientData() {
        contactKeys = new HashMap<>();
        conversations = new HashMap<>();
    }

    void createContact(String contactName, String key) {
        if (contactExists(contactName)) {
            // throw new RuntimeException("tried to create contact with existing contact name: " + contactName);
            return;
        }
        contactKeys.put(contactName, key);
        conversations.put(contactName, new Conversation(contactName));
    }

    void removeContact(String contactName) {
        contactKeys.remove(contactName);
        conversations.remove(contactName);
    }

    String getMySecretString() {
        return mySecretString;
    }

    void setMySecretString(String mySecretString) {
        this.mySecretString = mySecretString;
    }

    boolean contactExists(String contactName) {
        return (contactKeys.containsKey(contactName));
    }

    String getKey(String contactName) {
        return (contactKeys.get(contactName));
    }

    void setKey(String contactName, String key) {
        if (!contactExists(contactName)) {
            // throw new RuntimeException("tried to set the key for a non-existent contact: " + contactName);
            return;
        }
        contactKeys.put(contactName, key);
    }

    Conversation getConversation(String contactName) {
        return (conversations.get(contactName));
    }

    // get an iterator to allow us to iterate through all contacts (contact names)
    Iterator<String> getContactIterator() {
        return (contactKeys.keySet().iterator());
    }

    int getNumContacts() {
        return (contactKeys.size());
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
}
