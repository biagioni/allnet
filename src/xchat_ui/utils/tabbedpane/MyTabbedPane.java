package utils.tabbedpane;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import utils.BijectiveList;

/**
 * A JPanel containing a JTabbedPane.  Receives its own change events and 
 * repackages them as ActionEvents to send to its listener.
 * 
 * Tabs are referenced by id, not title.  
 * 
 * 
 * @author Henry
 */
public class MyTabbedPane extends JPanel implements ChangeListener, ActionListener {

    private static final long serialVersionUID = 1L;
    private JTabbedPane tabbedPane;
    private ActionListener listener;
    private String commandPrefix = "MyTabbedPane";
    // map id's to JPanels (tabs) and vice-versa
    private BijectiveList<String, Component> idToPanel;
    // images for the tab close buttons
    private Image buttonImg, buttonPressedImg, buttonOverImg;

    public MyTabbedPane() {
        tabbedPane = new JTabbedPane();
        tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        tabbedPane.addChangeListener(this);
        setLayout(new BorderLayout());
        add(tabbedPane, BorderLayout.CENTER);
        listener = null;
        idToPanel = new BijectiveList<>();
        loadImages();
    }

    public void addTab(String id, String title, JPanel panel) {
        addTab(0, id, title, panel);
    }
    
    public void addTabRight(String id, String title, JPanel panel) {
        addTab(tabbedPane.getTabCount(), id, title, panel);
    }

    private void addTab(int idx, String id, String title, JPanel panel) {
        panel.setName(title);
        tabbedPane.add(panel, idx);
        idToPanel.put(id, panel);
    }

    public void setTitle(String id, String newTitle) {
        Component wanted = idToPanel.getValueFor(id);
        if (wanted == null)
            return;
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            if (tabbedPane.getComponentAt(i) == wanted) {
                tabbedPane.setTitleAt(i, newTitle);
                return;
            }
        }
    }
    
    public void addTabWithClose(String id, String title, JPanel panel, String closeCommand) {
        addTabWithClose(0, id, title, panel,closeCommand);
    }
    
    public void addTabWithCloseRight(String id, String title, JPanel panel, String closeCommand) {
        addTabWithClose(tabbedPane.getTabCount(), id, title, panel,closeCommand);
    }
    

    private void addTabWithClose(int idx, String id, String title, JPanel panel, String closeCommand) {
        addTab(idx, id, title, panel);
        //
        JLabel tabLabel = new JLabel(title);
        tabLabel.setOpaque(false);
        tabLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
        tabLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        //
        SimpleButton tabButton = new SimpleButton(16, 16, buttonImg, buttonPressedImg, buttonOverImg);
        tabButton.setListener(listener, id, closeCommand);
        //
        JPanel tabPanel = new JPanel();
        tabPanel.setOpaque(false);
        tabPanel.setLayout(new BoxLayout(tabPanel, BoxLayout.X_AXIS));
        tabPanel.add(tabLabel);
        tabPanel.add(Box.createHorizontalStrut(4));
        tabPanel.add(tabButton);
        // tabPanel.setBorder(BorderFactory.createLineBorder(Color.BLACK));
        tabbedPane.setTabComponentAt(idx, tabPanel);
    }

    public void removeTab(String id) {
        Component panel = idToPanel.getValueFor(id);
        if (panel != null) {
            tabbedPane.remove(panel);
            idToPanel.remove(id);
        }
    }

    public String getCommandPrefix() {
        return commandPrefix;
    }

    public void setCommandPrefix(String commandPrefix) {
        this.commandPrefix = commandPrefix;
    }

    public void setListener(ActionListener listener) {
        this.listener = listener;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        // just forward the event
        if (listener != null) {
            listener.actionPerformed(e);
        }
    }

    @Override
    public void stateChanged(ChangeEvent e) {
        if (listener != null) {
            String command = commandPrefix + ":" + getSelectedID();
            ActionEvent ae = new ActionEvent(this, 0, command);
            listener.actionPerformed(ae);
        }
    }

    public void setSelected(String id) {
        Component panel = idToPanel.getValueFor(id);
        if (panel != null) {
            tabbedPane.setSelectedComponent(panel);
        }
    }

    public void setSelected(Component c) {
        tabbedPane.setSelectedComponent(c);
    }

    // returns the ID of the selected panel (tab)
    public String getSelectedID() {
        int idx = tabbedPane.getSelectedIndex();
        Component panel = tabbedPane.getComponentAt(idx);
        return (idToPanel.getKeyOf(panel));
    }

    public Component getSelectedComponent() {
        return (tabbedPane.getSelectedComponent());
    }

    public Component getTabContent(String id) {
        return (idToPanel.getValueFor(id));
    }

    // load all the images that we will need
    private void loadImages() {
        MediaTracker mt = new MediaTracker(this);
        Toolkit toolkit = Toolkit.getDefaultToolkit();
        // get the first-used images first
        buttonImg = toolkit.getImage(getClass().getResource("button.png"));
        buttonPressedImg = toolkit.getImage(getClass().getResource("pressed.png"));
        buttonOverImg = toolkit.getImage(getClass().getResource("mouseOver.png"));
        mt.addImage(buttonImg, 0);
        mt.addImage(buttonOverImg, 0);
        mt.addImage(buttonPressedImg, 0);
        // now wait till they're all loaded, or 4 sec max
        try {
            mt.waitForAll(4000);
        }
        catch (Exception e) {
            System.out.println(e);
        }
    }
}
