/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Class DataBaseManagerException.
 * 
 */

package be.ulg.vervier.SmtpDump.Result.DataBase;

public class DataBaseManagerException extends java.lang.Exception {
	
	/** An error occured while communicating with a database or executing a SQL
     * command. */
    public DataBaseManagerException(String msg) {
		super(msg);
    }
    
}
