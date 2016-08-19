
package utils;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BoxLayout;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTextPane;

/**
 * Class to create a "message bubble" as a JTextPane.
 *
 * A border can be added externally.
 *
 * @author henry
 * @param <MESSAGE>
 */
public class MessageBubble<MESSAGE> extends JPanel implements ActionListener {

    private static final String COPY = "Copy";
    private static final String COPY_ALL = "Copy All";

    // keep the message pane so we can change background later
    private JTextPane textPane;
    // keep a reference to the message that the Bubble renders, if desired
    private MESSAGE message;

    public MessageBubble(boolean leftJustified, Color color, String... lines) {
        this(null, leftJustified, color, lines);
    }

    public MessageBubble(MESSAGE message, boolean leftJustified, Color color, String... lines) {
        super();
        this.message = message;
        setBackground(color);
        textPane = new JTextPane();
        textPane.setContentType("text/html");
        textPane.setEditable(false);
        textPane.setBackground(color);
        textPane.setLayout(new BoxLayout(textPane, BoxLayout.Y_AXIS));
        String htmlPrefix;
        if (leftJustified) {
            htmlPrefix = "<STYLE type=\"text/css\"> BODY {text-align: left} </STYLE> <BODY>";
        }
        else {
            htmlPrefix = "<STYLE type=\"text/css\"> BODY {text-align: right} </STYLE> <BODY>";
        }
        StringBuilder sb = new StringBuilder(htmlPrefix);
        for (int i = 0; i < lines.length; i++) {
            sb.append(lines[i]);
            if (i < lines.length - 1) {
                sb.append("<br>");
            }
        }
        sb.append("</BODY>");
        textPane.setText(sb.toString());
        Dimension size = textPane.getPreferredScrollableViewportSize();
        textPane.setPreferredSize(size);
        textPane.setMaximumSize(size);
        //
        setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
        add(textPane);
        //setBorder(new RoundedBorder(borderColor, borderWidth, borderRadius, borderInset));

        // make a context menu
        JPopupMenu popup = new JPopupMenu();
        JMenuItem item = new JMenuItem(COPY);
        item.addActionListener(this);
        popup.add(item);
        item = new JMenuItem(COPY_ALL);
        item.addActionListener(this);
        popup.add(item);
        textPane.setComponentPopupMenu(popup);

    }

    public void setBubbleBackground(Color bg) {
        super.setBackground(bg);
        textPane.setBackground(bg);
    }

    public MESSAGE getMessage() {
        return (message);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String cmd = e.getActionCommand();
        switch (cmd) {
            case COPY:
                this.textPane.copy();
                break;
            case COPY_ALL:
                this.textPane.selectAll();
                this.textPane.copy();
                break;
            default:
                throw new RuntimeException("bad menu cmd");
        }
    }

}
