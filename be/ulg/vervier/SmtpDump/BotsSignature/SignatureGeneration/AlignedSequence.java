/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class represents a sequence of characters that has been aligned with
 * on or more other sequences of characters. This sequence is thus made of
 * characters and gaps which are caused by the alignment.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature.SignatureGeneration;

import java.util.List;

class AlignedSequence {
	
	/** INTSANCE VARIABLES */
	
	/** The list sequence as a list of characters. Gaps are associated with
	 * null characters. */
	private Character[] aligned_sequence;
	
	/** CONSTRUCTORS */
	
	/** Default constructor. */
	AlignedSequence() {}
	
	/** METHODS */
	
	/** Set the aligned sequence given the original sequence and the list of
	 * gaps sorted in ascending order. */
	void setAlignedSequence(String sequence, List<Integer> gaps) {
		if (sequence == null || (sequence != null && sequence.isEmpty()))
			return;
		aligned_sequence = new Character[sequence.length() + gaps.size()];
		int gaps_index = 0;
		int sequence_index = 0;
		// traverse the sequence and the list of gaps to build the aligned
		// version of the sequence
		for (int i = 0; i < aligned_sequence.length; i++) {
			if (gaps_index < gaps.size() &&
				gaps.get(gaps_index) == sequence_index) {
				aligned_sequence[i] = null;
				gaps_index++;
			} else {
				if (sequence_index < sequence.length()) {
					aligned_sequence[i] = sequence.charAt(sequence_index++);
				}
			}
		}
	}
	
	/** Return the character at the given position in the aligned sequence,
	 * "null" if there is a gap at the given position. */
	Character getCharAt(int i) {
		if (aligned_sequence == null ||
			i < 0 ||
			(aligned_sequence != null && i >= aligned_sequence.length))
			return null;
		return aligned_sequence[i];
	}
	
	/** Return the length of the aligned sequence. */
	int length() {
		return aligned_sequence != null ? aligned_sequence.length : -1;
	}
	
	/** Return the String representation of the aligned sequence. A gap is
	 * representated by a '_' (underscore). */
	public String toString() {
		if (aligned_sequence == null)
			return null;
		StringBuilder sb = new StringBuilder(aligned_sequence.length);
		for (int i = 0; i < aligned_sequence.length; i++)
			sb.append(getCharAt(i) == null ? "_" : getCharAt(i));
		return sb.toString();
	}
	
}
