package allnetui;


/**
 * This interface defines the public API methods for the application to 
 * communicate with the UI client
 * 
 * @author Henry
 */
public interface UIAPI {
    
    // the application should call this method after a valid message is received
    public void messageReceived(String from, long sentTime, String text);
    
    // the application should call this method after a message has been successfully sent
    public void messageSent(String to, long sentTime, String text);
    
    // the application should call this method to tell the UI about a new contact
    public void contactCreated(String contactName, String key);
    
    // the application should call this method to tell the UI to remove a contact
    public void contactDeleted(String contactName);
    
    // the application should call this method to update a user's key
    public void updateKey(String contactName, String key);
    
    
}
