package allnetui;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;

/**
 * Class to hold the client's data: contacts, keys, conversations.
 *
 * The data can be modified by class UIController through calls to its public
 * API.
 *
 *
 * @author Henry
 */
public class ContactData {

    // private String mySecretString;
    private HashMap<String, Contact> contacts;

    public ContactData() {
        contacts = new HashMap<>();
    }

    public void createContact(String contactName, ContactType type) {
        if (contactExists(contactName)) {
            // throw new RuntimeException("tried to create contact with existing contact name: " + contactName);
            return;
        }
        contacts.put(contactName, new Contact(contactName, type));
    }

    public void removeContact(String contactName) {
        contacts.remove(contactName);
    }

    public void clearConversation(String contactName) {
        Contact contact = contacts.get(contactName);
        contact.getConversation().clear();
    }

    public boolean contactExists(String contactName) {
        return (contacts.containsKey(contactName));
    }

    public boolean isBroadcast(String contactName) {
        try {
            return (contacts.get(contactName).isBroadcast());
        } catch (java.lang.NullPointerException e) {
            return false;
        }
    }

    public boolean isVisible(String contactName) {
        try {
            return (contacts.get(contactName).isVisible());
        } catch (java.lang.NullPointerException e) {
            return false;
        }
    }

    public Conversation getConversation(String contactName) {
        try {
            return (contacts.get(contactName).getConversation());
        } catch (java.lang.NullPointerException e) {
            return null;
        }
    }

    // get an iterator to allow us to iterate through
    // all contacts (contact names)
    public Iterator<String> getContactIterator() {
        try {
            return (contacts.keySet().iterator());
        } catch (java.lang.NullPointerException e) {
            return null;
        }
    }

    public Contact getContact(String contactName) {
        try {
            return (contacts.get(contactName));
        } catch (java.lang.NullPointerException e) {
            return null;
        }
    }

    public ArrayList<String> getGroupsList() {
        ArrayList<String> list = new ArrayList<>();
        Contact contact;
        for (String contactName : contacts.keySet()) {
            contact = contacts.get(contactName);
            if ((contact != null) && (contact.isGroup())) {
                list.add(contactName);
            }
        }
        Collections.sort(list);
        return (list);
    }

    public ArrayList<String> getContactsList() {
        ArrayList<String> list = new ArrayList<>();
        list.addAll(contacts.keySet());
        Collections.sort(list);
        return (list);
    }

    public int getNumContacts() {
        return (contacts.size());
    }

    public int getTotalNewMsgs() {
        Iterator<String> it = getContactIterator();
        if (it == null)
            return 0;
        int count = 0;
        Conversation conv;
        while (it.hasNext()) {
            conv = getConversation(it.next());
            if (conv != null)
                count += conv.getNumNewMsgs();
        }
        return (count);
    }

    public int getNumContactsWithNewMsgs() {
        Iterator<String> it = getContactIterator();
        if (it == null)
            return 0;
        int count = 0;
        Conversation conv;
        while (it.hasNext()) {
            conv = getConversation(it.next());
            if ((conv != null) && (conv.getNumNewMsgs() > 0)) {
                count++;
            }
        }
        return (count);
    }

    public int getNumNewMsgs(String contact) {
        Iterator<String> it = getContactIterator();
        if (it == null)
            return 0;
        int count = 0;
        Conversation conv;
        while (it.hasNext()) {
            conv = getConversation(it.next());
            if ((conv != null) && (contact.equals(conv.getOtherParty()))) {
                count += conv.getNumNewMsgs();
            }
        }
        return (count);
    }
}
