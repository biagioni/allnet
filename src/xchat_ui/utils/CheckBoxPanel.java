package utils;

import java.awt.GridLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;

/**
 * Checkboxes and labels in a grid layout
 *
 * @author henry
 */
public class CheckBoxPanel extends JPanel {

    private JCheckBox[] checkBoxes;

    public CheckBoxPanel(String... labelText) {
        super();
        JLabel[] labels = new JLabel[labelText.length];
        checkBoxes = new JCheckBox[labelText.length];
        for (int i = 0; i < labelText.length; i++) {
            labels[i] = new JLabel(labelText[i]);
            checkBoxes[i] = new JCheckBox();
            checkBoxes[i].setHorizontalAlignment(SwingConstants.CENTER);
        }
        setLayout(new GridLayout(labelText.length, 2, 5, 5));
        for (int i = 0; i < labelText.length; i++) {
            add(labels[i]);
            add(checkBoxes[i]);
        }
    }

    public JCheckBox[] getCheckBoxes() {
        return checkBoxes;
    }

    public void init(boolean... selected) {
        for (int i = 0; i < Math.min(selected.length, checkBoxes.length); i++) {
            checkBoxes[i].setSelected(selected[i]);
        }
    }

    public void init() {
        for (JCheckBox checkBoxe : checkBoxes) {
            checkBoxe.setSelected(false);
        }
    }

}
