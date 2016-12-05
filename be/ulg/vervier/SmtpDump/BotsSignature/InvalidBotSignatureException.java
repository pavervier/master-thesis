/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Class InvalidBotSignatureException.
 *
 */

package be.ulg.vervier.SmtpDump.BotsSignature;

public class InvalidBotSignatureException extends SignatureParserException {
	
	/** An invalid signature has been found in the signature file. */
    public InvalidBotSignatureException() {
		super("invalid signature found");
    }
}
