/**
 * Pierre-Antoine Vervier (University of Liège)
 * 
 * Protocol learning techniques for the automated detection of spambots
 * 
 * Class SignatureFileWriterException.
 *
 */

package be.ulg.vervier.SmtpDump.BotsSignature.SignatureGeneration;

public class SignatureFileWriterException extends java.io.IOException {
	
	/** An error occured while manipulating the file or writing signatures to
	 * the file. */
    public SignatureFileWriterException(String msg) {
		super(msg);
    }
}
