package cuchaz.enigma.source.tda;

import java.util.ArrayList;
import java.util.Collection;

import org.objectweb.asm.tree.LabelNode;

public class LabelSurrogate extends UnarySurrogate<LabelNode> {

	public final Collection<InstructionSurrogate> backreferences = new ArrayList<>();
	private String name;

	public LabelSurrogate(LabelNode label) {
		super(label);
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		if (name == null) {
			throw new IllegalStateException("Label surrogate with no attached name.");
		}
		return name;
	}

	@Override
	public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
		if (name == null) {
			throw new IllegalStateException("Label surrogate with no attached name.");
		}
		outString.append(name).appendCodePoint(':');
		return startIndex + name.length() + 1;
	}
}
