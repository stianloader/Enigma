package cuchaz.enigma.source.tda;

import java.util.Objects;

import org.checkerframework.checker.index.qual.NonNegative;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

public class Token {
	@NonNegative
	public final int start;
	@NonNegative
	public final int end;
	@NonNull
	public final String fqnClass;
	@Nullable
	public final String memberName;
	@Nullable
	public final String memberDesc;

	public Token(int start, int end, String fqnClass, String memberName, String memberDesc) {
		if (start < 0) {
			throw new IndexOutOfBoundsException("Token start index is negative (" + start + ")");
		}
		if (end < 0) {
			throw new IndexOutOfBoundsException("Token end index is negative (" + end + ")");
		}
		if ((memberName == null) ^ (memberDesc == null)) {
			throw new IllegalArgumentException("If memberName is null memberDesc needs to also be null and vice versa. Currently: " + memberName + ", " + memberDesc);
		}
		this.start = start;
		this.end = end;
		this.fqnClass = Objects.requireNonNull(fqnClass, "fqnClass may not be null");
		this.memberName = memberName;
		this.memberDesc = memberDesc;
	}
}
