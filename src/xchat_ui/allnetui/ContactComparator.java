package allnetui;

public class ContactComparator implements java.util.Comparator<String> {

    private ContactData clientData = null;

    public ContactComparator(ContactData data) {
        clientData = data;
    }

    @Override
    public int compare(String s1, String s2) {
        if (s1 == s2)
            return 0;
        if (s1 == null)   // s1 < s2, since s2 is not null
            return -1;
        if (s2 == null)   // s1 > s2, since s2 is not null
            return 1;
        if (s1.equals (s2))
            return 0;
        Conversation conv1 = clientData.getConversation(s1);
        Conversation conv2 = clientData.getConversation(s2);
        if (conv1 == null)
            throw new RuntimeException("tried to compare contact: " + s1);
        if (conv2 == null)
            throw new RuntimeException("tried to compare contact: " + s2);
        long lastMsgTime1 = conv1.getLastRxMessageTime();
        long lastMsgTime2 = conv2.getLastRxMessageTime();
        if (lastMsgTime1 > lastMsgTime2)
            return -1;
        if (lastMsgTime1 < lastMsgTime2)
            return 1;
        return s1.compareToIgnoreCase(s2);
    }

}
