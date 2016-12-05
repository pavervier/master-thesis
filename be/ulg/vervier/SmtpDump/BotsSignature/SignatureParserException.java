/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Class SignatureParserException.
 *
 */

package be.ulg.vervier.SmtpDump.BotsSignature;

public class SignatureParserException extends java.io.IOException {
	
	/** An error occured while reading from the signature file. */
    public SignatureParserException(String msg) {
		super(msg);
    }
}
