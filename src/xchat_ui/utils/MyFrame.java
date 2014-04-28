package utils;

import java.awt.Dimension;
import java.awt.Point;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import javax.swing.JFrame;

/**
 * Abstract class to create a UI Frame and provide a common set of functions and
 * definitions.
 *
 *
 * @author Henry
 */
public class MyFrame extends JFrame implements WindowListener, ActionListener {

    private static final long serialVersionUID = 1L;

    /**
     * Makes a JFrame with application support methods.
     */
    public MyFrame() {
        super();
        // rely on window listener event to shut down safely
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(this);
    }

    /**
     * Sets the frame's location
     * @param x x coordinate
     * @param y y coordinate
     */
    public void setMyLocation(int x, int y) {
        Point pt;
        Dimension wSize = getSize();
        Dimension scrSize = Toolkit.getDefaultToolkit().getScreenSize();
        // test if window fits where we're told to put it
        if ((x >= 0) && (y >= 0) && (x + wSize.width < scrSize.width) && (y + wSize.height < scrSize.height)) {
            pt = new Point(x, y);
        }
        else {
            // put it in the center
            pt = new Point((scrSize.width - wSize.width) / 2,
                    (scrSize.height - wSize.height) / 2);
        }
        setLocation(pt);
    }

    /**
     * Sets the frame's location
     * @param x x coordinate
     * @param y y coordinate
     */
    public void setMyLocation(String location) {
        if (location.toLowerCase().contains("center")) {
            putInCenter();
            return;
        }
        // now parse location
        int x, y;
        try {
            String[] xy = location.split(",");
            x = Integer.parseInt(xy[0].trim());
            y = Integer.parseInt(xy[1].trim());
        }
        catch (Exception e) {
            putInCenter();
            return;
        }
        Point pt;
        Dimension wSize = getSize();
        Dimension scrSize = Toolkit.getDefaultToolkit().getScreenSize();

        // test if window fits where we're told to put it
        if ((x >= 0) && (y >= 0) && (x + wSize.width < scrSize.width) && (y + wSize.height < scrSize.height)) {
            pt = new Point(x, y);
        }
        else {
            // put it in the center
            pt = new Point((scrSize.width - wSize.width) / 2,
                    (scrSize.height - wSize.height) / 2);
        }
        setLocation(pt);
    }

    public void putInCenter() {
        Point pt;
        Dimension wSize = getSize();
        Dimension scrSize = Toolkit.getDefaultToolkit().getScreenSize();
        pt = new Point((scrSize.width - wSize.width) / 2,
                (scrSize.height - wSize.height) / 2);
        setLocation(pt);
    }

    /**
     * The window listener methods can simply be overridden as required. Default
     * action on close is to dispose and exit.  Override these methods for
     * different behavior.
     *
     * @param e the WindowEvent
     */
    @Override
    public void windowClosing(WindowEvent e) {
        dispose();
        System.exit(0);
    }

    /**
     * Empty method can be overridden by subclass.
     *
     * @param e  WindowEvent
     */
    @Override
    public void windowActivated(WindowEvent e) {
    }

    /**
     * Empty method can be overridden by subclass.
     *
     * @param e  WindowEvent
     */
    @Override
    public void windowClosed(WindowEvent e) {
    }

    /**
     * Empty method can be overridden by subclass.
     *
     * @param e  WindowEvent
     */
    @Override
    public void windowDeactivated(WindowEvent e) {
    }

    /**
     * Empty method can be overridden by subclass.
     *
     * @param e  WindowEvent
     */
    @Override
    public void windowDeiconified(WindowEvent e) {
    }

    /**
     * Empty method can be overridden by subclass.
     *
     * @param e  WindowEvent
     */
    @Override
    public void windowIconified(WindowEvent e) {
    }

    /**
     * Empty method can be overridden by subclass.
     *
     * @param e  WindowEvent
     */
    @Override
    public void windowOpened(WindowEvent e) {
    }

    /**
     * Empty method can be overridden by subclass.
     *
     * @param e ActionEvent
     */
    @Override
    public void actionPerformed(ActionEvent e) {
    }
}
