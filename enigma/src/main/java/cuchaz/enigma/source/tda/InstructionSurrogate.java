package cuchaz.enigma.source.tda;

import java.util.Collection;

public interface InstructionSurrogate {
	/**
	 * Write the stringified variant of the instruction surrogate.
	 *
	 * @param outString The builder to write the stringified version to
	 * @param tokenOut The collection to push tokens to, if any tokens are possible
	 * @param startIndex The position from which this instruction surrgate writes from (not directly linked to the write position of the output builder).
	 * @return The index at which the write head is now located at.
	 */
	int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex);

	boolean allowInline();
}
