/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Class InputReaderException.
 *
 */

package be.ulg.vervier.SmtpDump.NetworkDataCapture;

public class PacketCaptorException extends java.io.IOException {
	
	/** Unable to read from the input resource. */
    public PacketCaptorException(String msg) {
		super(msg);
    }
}
