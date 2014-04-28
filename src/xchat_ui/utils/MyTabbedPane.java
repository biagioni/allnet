package utils;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * A JTabbedPane that receives its own change events and repackages them
 * as ActionEvents to send to its listener.
 * 
 * 
 * @author Henry
 */
public class MyTabbedPane extends JTabbedPane implements ChangeListener {

    private static final long serialVersionUID = 1L;
    private ActionListener listener;
    private String commandPrefix = "MyTabbedPane";

    public MyTabbedPane() {
        super();
        setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        addChangeListener(this);
        listener = null;
    }

    public void addPanel(String title, JPanel panel) {
        add(title, panel);
    }

    public void removeTab(String title) {
        int idx = this.indexOfTab(title);
        if (idx >= 0) {
            this.remove(idx);
        }
    }

    public void selectTab(String title) {
        int idx = this.indexOfTab(title);
        if (idx >= 0) {
            setSelectedIndex(idx);
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

    // for convenience, make a JPanel and drop this component in it.
    public JPanel putInPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout());
        panel.add(this, BorderLayout.CENTER);
        return (panel);
    }

    @Override
    public void stateChanged(ChangeEvent e) {
        if (listener != null) {
            int idx = getSelectedIndex();
            String tabName = getTitleAt(idx);
            String command = commandPrefix + ":" + tabName;
            ActionEvent ae = new ActionEvent(this, 0, command);
            listener.actionPerformed(ae);
        }
    }

    public String getCurrentTab() {
        int idx = getSelectedIndex();
        String tabName = getTitleAt(idx);
        return (tabName);
    }

    public Component getTabContent(String title) {
        int idx = this.indexOfTab(title);
        if (idx >= 0) {
            return (getComponentAt(idx));
        }
        return (null);
    }
}
