/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class is responsible for writing signatures to a given file. A signature
 * is written to the file by consecutively writing each statement in the order
 * they are defined in the signature.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature.SignatureGeneration;

import java.io.FileWriter;
import java.io.IOException;

class SignatureFileWriter {
	
	/** INSTANCE VARIABLES */
	
	/** The signature destination file name */
	private String file_name;
	/** The file output stream */
	private FileWriter fr;
	/** Signature file writer buffer (signatures are written to file once they
	 * are finalized) */
	private StringBuilder sig_buffer;
	/** True if a file is currently open, false otherwise */
	private boolean file_open;
	
	/** CONSTRUCTOR */
	
	/** Default constructor. */
	SignatureFileWriter() {
		file_open = false;
	}
	
	/** METHODS */
	
	/** Open the file for writing signatures. If another file is already opened,
	 * this file is closed and the new one is created. */
	void openFile(String file_name) throws SignatureFileWriterException {
		if (file_name == null) return;
		if (file_open)
			closeFile();
		try {
			fr = new FileWriter(file_name);
		} catch (IOException ioe) {
			throw new SignatureFileWriterException
			("signature-file-writer:" + ioe.getMessage());
		}
		file_open = true;
	}
	
	/** Begin the writing of a new signature given its identifier. */
	void openNewSignature(String identifier)
		throws SignatureFileWriterException {
		if(!file_open) return;
		sig_buffer = new StringBuilder();
		sig_buffer.append("\nsig \"").
		append(identifier == null ? "" : identifier).
		append("\" {");
	}
	
	/** Write the given statement to the file. A statement consists in a
	 * protocol part followed by a value part. */
	void writeStatement(String protocol, String value)
		throws SignatureFileWriterException {
		if(!file_open || sig_buffer == null) return;
		sig_buffer.append("\n").
		append(protocol).
		append(":").
		append(value).
		append(";");
	}
	
	/** Write a TCP open statement. */
	void writeTCPOpen()
		throws SignatureFileWriterException {
		writeStatement("    tcp", "open");
	}
		
	/** Write a TCP close statement. */
	void writeTCPClose()
		throws SignatureFileWriterException {
		writeStatement("    tcp", "close");
	}
	
	/** Write a TCP reset statement. */
	void writeTCPReset()
		throws SignatureFileWriterException {
		writeStatement("    tcp", "reset");
	}
	
	/** Write the given SMTP statement to the file. */
	void writeSMTPStatement(String statement)
		throws SignatureFileWriterException {
		writeStatement("        smtp", "\"" + (statement == null ?
                       "" : statement.replace("\"", "$dquote$").
                       replace(";", "$semicolon$")) + "\"");
	}
	
	/** Write the given IMF statement to the file. */
	void writeIMFStatement(String statement)
		throws SignatureFileWriterException {
		writeStatement("            imf", "\"" + (statement == null ?
                       "" : statement.replace("\"", "$dquote$").
                       replace(";", "$semicolon$")) + "\"");
	}
	
	/** End the writing of the current signature. */
	void endSignature()throws SignatureFileWriterException {
		if(!file_open || sig_buffer == null) return;
		try {
			sig_buffer.append("\n}\n");
			fr.write(sig_buffer.toString());
		} catch (IOException ioe) {
			throw new SignatureFileWriterException
			("signature-file-writer:" + ioe.getMessage());
		}
	}
	
	/** Close the currently open file, if any. */
	void closeFile() throws SignatureFileWriterException {
		if (!file_open) return;
		try {
			fr.close();
		} catch (IOException ioe) {
			throw new SignatureFileWriterException
			("signature-file-writer:" + ioe.getMessage());
		}
		fr = null;
		file_open = false;
	}
	
}
