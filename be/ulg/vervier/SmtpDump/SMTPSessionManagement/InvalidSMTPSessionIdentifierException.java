/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Class InvalidSMTPSessionIdentifierException.
 *
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

public class InvalidSMTPSessionIdentifierException extends java.io.IOException {
	
	/** An invalid SMTP session identifier (i.e. server IP, client IP, server
     * port number and client port number) was detected while creating a new
     * SMTP session. */
    public InvalidSMTPSessionIdentifierException() {
		super("invalid smtp session identifier" +
              "(src-ip, dst-ip, src-port, dst-port)");
    }
}
