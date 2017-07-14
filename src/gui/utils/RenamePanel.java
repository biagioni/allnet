package utils;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

/**
 *
 * @author henry
 */
public class RenamePanel extends JPanel implements ActionListener {

    private JTextField nameField;
    private JCheckBox checkBox;

    public RenamePanel() {
        nameField = new JTextField();
        nameField.setEnabled(false);
        checkBox = new JCheckBox();
        checkBox.setHorizontalAlignment(SwingConstants.CENTER);
        checkBox.setSelected(false);
        checkBox.addActionListener(this);
        JLabel checkLabel = new JLabel("Rename Contact?");
        JLabel textLabel = new JLabel("New Contact Name:");
        setLayout(new GridLayout(2, 2, 5, 5));
        add(checkLabel);
        add(checkBox);
        add(textLabel);
        add(nameField);
        init();
    }

    public String getNameField() {
        if (checkBox.isSelected()) {
            return (nameField.getText());
        }
        else {
            return (null);
        }
    }

    public final void init() {
        checkBox.setSelected(false);
        nameField.setText("");
        nameField.setEnabled(false);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() != checkBox) {
            return;
        }
        // clear name field whenever checkbox is changed
        nameField.setText("");
        if (checkBox.isSelected()) {
            nameField.setEnabled(true);
        }
        else {
            nameField.setEnabled(false);
        }
        
    }
    
}
