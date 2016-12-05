/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Class SMTPParserException.
 *
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

public class SMTPParserException extends java.io.IOException {
	
	/** An error occured while parsing the SMTP session. */
    public SMTPParserException(String msg) {
		super(msg);
    }
}
