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
    private static final String fname = "screen_location.txt";
    private static final String home = System.getProperty("user.home");
    private static final java.nio.file.Path fpath =
        java.nio.file.Paths.get(home, ".allnet", "xchat", fname);

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

        int bsize = 6;   // let the border be out of the screen
        // test if window fits where we're told to put it
        if ((x >= 0) && (y >= 0) && (x + wSize.width <= scrSize.width + bsize) && (y + wSize.height <= scrSize.height + bsize)) {
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
     * Sets the frame's size
     * @param w,h desired width and height
     */
    public void setMySize(String size) {
        int w = 435;  // default size (as of 2020/02/18)
        int h = 588;
        // now parse location
        try {
            if (! size.toLowerCase().contains("default")) {
                String[] wh = size.split(",");
                w = Integer.parseInt(wh[0].trim());
                h = Integer.parseInt(wh[1].trim());
            }
        }
        catch (Exception e) {
            putInCenter();
            return;
        }
        // guarantee sensible minimum sizes
        if (w < 250) w = 250;
        if (h < 250) h = 250;
        setSize(w, h);
    }

    public boolean useSavedLocation() {
        try {
            java.util.List<String> lines =
                java.nio.file.Files.readAllLines(fpath);
            if (lines.size() > 0) {
                if (lines.size() > 1) {
                    setMySize(lines.get(1));
                }
                setMyLocation(lines.get(0));
                return true;
            }
        } catch (java.nio.file.NoSuchFileException e) {  // silent
        } catch (Exception e) {  // report
           System.out.println (e);
        }
        return false;
    }

    public void saveLocation() {
        String location = new String(getX() + "," + getY() + "\n" +
                                     getSize().width + "," + getSize().height);
        java.util.List<String> lines = new java.util.LinkedList<String>();
        lines.add(location);
        try {
            java.nio.file.Files.write(fpath, lines);
        } catch (java.nio.file.NoSuchFileException e) {  // silent
        } catch (Exception e) {
           System.out.println (e);
        }
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
