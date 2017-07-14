package utils;

import java.awt.event.WindowEvent;
import javax.swing.JPanel;

/**
 * Class to create a frame to hold an ApplicationPanel.
 *
 * @author Henry
 */
public class ApplicationFrame extends MyFrame {
    // just to avoid a warning
    private static final long serialVersionUID = 1L;
    // the application's controller
    private ControllerInterface controller;


    public ApplicationFrame(String title, JPanel appPanel, ControllerInterface controller, boolean resizeOkay) {
        // save ref to the Controller
        this.controller = controller;
        // give controller a ref to the frame it's running in 
        // (for example, so it can save the screen position on exit)
        controller.setFrame(this);
        // set the frame's title
        setTitle(title);
        // set the content
        setContentPane(appPanel);
        // setResizable(false) must come before pack(), otherwise pack doesn't
        // work correctly - seems like a swing bug
        setResizable(resizeOkay);
        pack();
    }

    /**
     * Override the windowClosing method to call the Controller's exit method.
     *
     * @param e the window event
     */
    @Override
    public void windowClosing(WindowEvent e) {
        controller.exit();
    }

}
