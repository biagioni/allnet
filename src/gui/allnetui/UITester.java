package allnetui;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.*;

/**
 * Manually send messages to the UI for testing
 * 
 * 
 * @author Henry
 */
class UITester extends JFrame implements ActionListener {

    private static final long serialVersionUID = 1L;
    private final String createStr = "createContact";
    private final String deleteStr = "deleteContact";
    private final String sendStr = "sendMsg";
    private final String receiveStr = "receiveMsg";
    //
    private UIController controller;
    private JTextField toFrom;
    private JTextField msg;
    private JCheckBox broadcastCheckBox;

    UITester(UIController controller) {
        super("AllNet Java UI Tester");
        this.controller = controller;
        JLabel toFromLabel = new JLabel("to / from");
        JLabel msgLabel = new JLabel("message / key");
        toFrom = new JTextField();
        msg = new JTextField();
        //
        JLabel broadcastLabel = new JLabel(" broadcast?");
        broadcastCheckBox = new JCheckBox();
        JPanel broadcastPanel = new JPanel();
        broadcastPanel.setLayout(new BoxLayout(broadcastPanel, BoxLayout.X_AXIS));
        broadcastPanel.add(broadcastCheckBox);
        broadcastPanel.add(broadcastLabel);
        //
        JButton send = new JButton(sendStr);
        send.addActionListener(this);
        JButton receive = new JButton(receiveStr);
        receive.addActionListener(this);
        JButton create = new JButton(createStr);
        create.addActionListener(this);
        JButton delete = new JButton(deleteStr);
        delete.addActionListener(this);
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridheight = 1;
        gbc.gridwidth = 1;
        gbc.weightx = 0.25;
        panel.add(toFromLabel, gbc);
        gbc.gridx++;
        gbc.weightx = 1.0;
        panel.add(msgLabel, gbc);
        gbc.weightx = 0.0;
        gbc.gridx++;
        gbc.gridy = 1;
        panel.add(receive, gbc);
        gbc.gridx++;
        panel.add(send, gbc);
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0.25;
        panel.add(toFrom, gbc);
        gbc.gridx++;
        gbc.weightx = 1.0;
        panel.add(msg, gbc);
        gbc.gridy = 2;
        gbc.gridx = 2;
        gbc.weightx = 0.0;
        panel.add(create, gbc);
        gbc.gridx++;
        panel.add(delete, gbc);
        // add broadcast label and check box
        gbc.gridx = 0;
        gbc.gridy = 2;
        panel.add(broadcastPanel, gbc);
        //
        gbc.gridy = 3;
        gbc.gridx = 0;
        gbc.gridwidth = 4;
        panel.add(Box.createRigidArea(new Dimension(600, 0)), gbc);
        setContentPane(panel);
        setResizable(false);
        pack();
        setLocation(10, 10);
        setVisible(true);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        long rcvdSeq = 0;
        String cmd = e.getActionCommand();
        switch (cmd) {
            case receiveStr:
                controller.messageReceived(toFrom.getText(),
                        System.currentTimeMillis(), rcvdSeq++,
                        msg.getText(), broadcastCheckBox.isSelected());
                break;
            case sendStr:
                controller.messageSent(toFrom.getText(),
                        System.currentTimeMillis(), 1, msg.getText());
                break;
            case createStr:
                if (broadcastCheckBox.isSelected()) {
                    controller.subscriptionComplete(toFrom.getText());
                }
                else {
                    controller.contactCreated(toFrom.getText());
                }
                break;
            case deleteStr:
                controller.contactDeleted(toFrom.getText());
                break;
        }

    }
}
