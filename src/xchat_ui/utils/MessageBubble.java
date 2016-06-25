package utils;

import java.awt.Color;
import java.awt.Dimension;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.JTextPane;

/**
 * Class to create a "message bubble" as a JTextPane.
 *
 * A border can be added externally.
 *
 * @author henry
 * @param <MESSAGE>
 */
public class MessageBubble<MESSAGE> extends JPanel {

    // keep the message pane so we can change background later
    private JTextPane area;
    // keep a reference to the message that the Bubble renders, if desired
    private MESSAGE message;

    public MessageBubble(boolean leftJustified, Color color, String... lines) {
        this(null, leftJustified, color, lines);
    }

    public MessageBubble(MESSAGE message, boolean leftJustified, Color color, String... lines) {
        super();
        this.message = message;
        setBackground(color);
        area = new JTextPane();
        area.setContentType("text/html");
        area.setEditable(false);
        area.setBackground(color);
        area.setLayout(new BoxLayout(area, BoxLayout.Y_AXIS));
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
        area.setText(sb.toString());
        Dimension size = area.getPreferredScrollableViewportSize();
        area.setPreferredSize(size);
        area.setMaximumSize(size);
        //
        setLayout(new BoxLayout(this, BoxLayout.X_AXIS));
        add(area);
        //setBorder(new RoundedBorder(borderColor, borderWidth, borderRadius, borderInset));
    }

    public void setBubbleBackground(Color bg) {
        super.setBackground(bg);
        area.setBackground(bg);
    }

    public MESSAGE getMessage() {
        return (message);
    }

}
