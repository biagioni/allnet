package allnetui;

import java.util.ArrayList;

/**
 * Class to define a contact.
 *
 * @author henry
 */
public class Contact {

    private static int nextContactID = 1000;
    private final int id;
    //
    private String name;
    private Conversation conversation;
    private ContactType type;
    //
    private boolean notify, saveMessages, visible;
    private ArrayList<String> groups;

    public Contact(String name, ContactType type) {
        id = nextContactID;
        nextContactID++;
        this.name = name;
        this.type = type;
        conversation = new Conversation(name);
        notify = saveMessages = visible = true;
        groups = new ArrayList<>();
    }

    public boolean isBroadcast() {
        return (type == ContactType.BROADCAST);
    }

    public boolean isGroup() {
        return (type == ContactType.GROUP);
    }

    public int getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public Conversation getConversation() {
        return conversation;
    }

    public ArrayList<String> getGroups() {
        return groups;
    }
    
    public boolean isNotify() {
        return notify;
    }

    public boolean isSaveMessages() {
        return saveMessages;
    }

    public boolean isVisible() {
        return visible;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setNotify(boolean notify) {
        this.notify = notify;
    }

    public void setSaveMessages(boolean saveMessages) {
        this.saveMessages = saveMessages;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
    }

    public void addGroup(String group) {
        if (groups.contains(group)) {
            throw new RuntimeException("tried to add duplicate group");
        }
        groups.add(group);
    }

}
