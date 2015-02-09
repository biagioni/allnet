package utils;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

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
    // private BasicTabbedPaneUI tpui;

    public MyTabbedPane() {
        tabbedPane = new JTabbedPane();
        tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        tabbedPane.addChangeListener(this);
        // tpui = new BasicTabbedPaneUI();
        // tabbedPane.setUI(tpui);
        setLayout(new BorderLayout());
        add(tabbedPane, BorderLayout.CENTER);
        listener = null;
        idToPanel = new BijectiveList<>();
    }

    public void addTab(String id, String title, JPanel panel) {
        panel.setName(title);
        tabbedPane.add(panel, 0);
        idToPanel.put(id, panel);
    }

    public void addTabWithClose(String id, String title, JPanel panel, String closeCommand) {
        addTab(id, title, panel);
        //
        JLabel tabLabel = new JLabel(title);
        tabLabel.setOpaque(false);
        tabLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
        tabLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        //
        JButton tabButton = new TabButton(this, id, closeCommand);
        tabButton.setMargin(new Insets(2,2,2,0));
        tabButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        //
        JPanel tabPanel = new JPanel();
        tabPanel.setOpaque(false);
        tabPanel.setLayout(new BoxLayout(tabPanel, BoxLayout.X_AXIS));
        tabPanel.add(tabLabel);
        tabPanel.add(Box.createHorizontalStrut(4));
        tabPanel.add(tabButton);
        // tabPanel.setBorder(BorderFactory.createLineBorder(Color.BLACK));
        tabbedPane.setTabComponentAt(0, tabPanel);
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

}
