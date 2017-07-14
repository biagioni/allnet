package utils;

import java.awt.event.ActionListener;

/**
 *
 * @author Henry
 */
public interface ControllerInterface extends ActionListener {

    // called to exit the program
    public void exit();
    
    // let controller know that it's running inside an ApplicationFrame, so it
    // can set or save the frame position 
    public void setFrame(ApplicationFrame frame);
    
}
