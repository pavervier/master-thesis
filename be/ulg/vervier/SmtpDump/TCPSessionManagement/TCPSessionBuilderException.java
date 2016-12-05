/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Class TCPSessionBuilderException.
 *
 */

package be.ulg.vervier.SmtpDump.TCPSessionManagement;

public class TCPSessionBuilderException extends java.io.IOException {
	
	/** An error occured while building the session. */
    public TCPSessionBuilderException(String msg) {
		super(msg);
    }
}
