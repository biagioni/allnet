package utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author Henry
 */
public class TextValidator  {

    private Pattern pattern;
    private int minLength;    

    public TextValidator(String regex, int minLength) {
        this.minLength = minLength;
        pattern = Pattern.compile(regex);
    }
    
       
    // returns true if the text is okay (matches regex and length >= minLength)
    public boolean isOkay(String text) {
        if ((text == null) || (text.length() < minLength))
                return(false);
        Matcher matcher = pattern.matcher(text);
        return(matcher.matches());
    }
    
}
