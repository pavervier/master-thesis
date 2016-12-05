/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a java.util.logging.Formatter. A formatter is
 * responsible of formating log reports output from java.util.logging.Logger
 * instances.
 * 
 */

package be.ulg.vervier.SmtpDump.Utils;

public class SimpleLogFormatter extends java.util.logging.Formatter {
    
    /** CONSRUCTOR */
    
    /** Default constructor. */
    public SimpleLogFormatter() { super(); }
    
    /** METHOD */
    
    /** Format the given log record and return the formatted string. */
    public String format(java.util.logging.LogRecord record) {
        return record.getMessage();
    }
    
}
