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
        return (contacts.get(contactName).isBroadcast());
    }

    public boolean isVisible(String contactName) {
        return (contacts.get(contactName).isVisible());
    }

    public Conversation getConversation(String contactName) {
        return (contacts.get(contactName).getConversation());
    }

    // get an iterator to allow us to iterate through
    // all contacts (contact names)
    public Iterator<String> getContactIterator() {
        return (contacts.keySet().iterator());
    }

    public Contact getContact(String contactName) {
        return (contacts.get(contactName));
    }

    public ArrayList<String> getGroupsList() {
        ArrayList<String> list = new ArrayList<>();
        Contact contact;
        for (String contactName : contacts.keySet()) {
            contact = contacts.get(contactName);
            if (contact.isGroup()) {
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
        int count = 0;
        Conversation conv;
        while (it.hasNext()) {
            conv = getConversation(it.next());
            count += conv.getNumNewMsgs();
        }
        return (count);
    }

    public int getNumContactsWithNewMsgs() {
        Iterator<String> it = getContactIterator();
        int count = 0;
        Conversation conv;
        while (it.hasNext()) {
            conv = getConversation(it.next());
            if (conv.getNumNewMsgs() > 0) {
                count++;
            }
        }
        return (count);
    }

    public int getNumNewMsgs(String contact) {
        Iterator<String> it = getContactIterator();
        int count = 0;
        Conversation conv;
        while (it.hasNext()) {
            conv = getConversation(it.next());
            if (contact.equals(conv.getOtherParty())) {
                count += conv.getNumNewMsgs();
            }
        }
        return (count);
    }
}
