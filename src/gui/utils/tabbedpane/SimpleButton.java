/*
 * SimpleButton.java
 *
 * Created on January 14, 2008, 6:59 PM
 * Modified 11 Feb 2015
 *
 * @author Henry
 */
package utils.tabbedpane;

import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Image;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import javax.swing.JPanel;

// class to implement a simple button
public class SimpleButton extends JPanel implements MouseListener {

    private static final long serialVersionUID = 1L;
    // mouse state control variables
    private boolean buttonPressed, buttonMouseOver;
    // images for button in, out, disabled
    private Image buttonImg;
    private Image buttonPressedImg;
    private Image buttonOverImg;
    private ActionListener listener;
    private String id, command;

    /** Creates a new instance of SimpleButton */
    public SimpleButton(int width, int height,
            Image buttonImg, Image buttonPressedImg,
            Image buttonOverImg) {
        this.buttonImg = buttonImg;
        this.buttonPressedImg = buttonPressedImg;
        this.buttonOverImg = buttonOverImg;
        setOpaque(false);
        Dimension d = new Dimension(width, height);
        setMinimumSize(d);
        setPreferredSize(d);
        setMaximumSize(d);
        buttonPressed = false;
        buttonMouseOver = false;
        listener = null;
        addMouseListener(this);
    }

    public void setListener(ActionListener listener, String id, String command) {
        this.listener = listener;
        this.id = id;
        this.command = command;
    }

    // ----------------   mouse interface   ----------------- //
    @Override
    public void mouseClicked(MouseEvent e) {
        traceMouseEvent(e);
    }

    @Override
    public void mousePressed(MouseEvent e) {
        traceMouseEvent(e);
        buttonPressed = true;
        repaint();
    }

    @Override
    public void mouseReleased(MouseEvent e) {
        traceMouseEvent(e);
        buttonPressed = false;
        repaint();
        if ((buttonMouseOver) && (listener != null)) {
            String actionCommand = id + ":" + command;
            ActionEvent ae = new ActionEvent(this, 0, actionCommand);
            listener.actionPerformed(ae);
        }
    }

    @Override
    public void mouseEntered(MouseEvent e) {
        traceMouseEvent(e);
        buttonMouseOver = true;
        repaint();
    }

    @Override
    public void mouseExited(MouseEvent e) {
        traceMouseEvent(e);
        buttonMouseOver = false;
        repaint();
    }

    // for debug
    private void traceMouseEvent(MouseEvent e) {
        // System.out.println(e);
    }

    // ----------------   painting stuff   ----------------- //
    @Override
    public void paintComponent(Graphics g) {
        super.paintComponent(g);
        if (buttonPressed && buttonMouseOver) {
            g.drawImage(buttonPressedImg, 0, 0, this);
        }
        else if (buttonMouseOver) {
            g.drawImage(buttonOverImg, 0, 0, this);
        }
        else {
            g.drawImage(buttonImg, 0, 0, this);
        }
    }
}
