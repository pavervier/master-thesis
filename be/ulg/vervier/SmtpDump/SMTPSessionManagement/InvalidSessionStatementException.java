/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Class InvalidSessionStatementException.
 *
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

public class InvalidSessionStatementException extends java.io.IOException {
	
	/** Exception thrown when an invalid (null or empty) SMTP statement
     * (command or response) is encountered while parsing a SMTP session. */
    public InvalidSessionStatementException() {
		super("invalid SMTP session statement found");
    }
}
