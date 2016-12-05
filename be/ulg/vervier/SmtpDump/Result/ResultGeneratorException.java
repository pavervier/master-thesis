/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Class ResultGeneratorException.
 * 
 */

package be.ulg.vervier.SmtpDump.Result;

public class ResultGeneratorException extends java.lang.Exception {
	
	/** An error occured while generating the results and storing them in the
     * database. */
    public ResultGeneratorException(String msg) {
		super(msg);
    }
    
}
