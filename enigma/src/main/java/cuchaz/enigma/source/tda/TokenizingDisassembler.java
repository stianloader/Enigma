package cuchaz.enigma.source.tda;

import org.checkerframework.checker.nullness.qual.Nullable;
import org.objectweb.asm.tree.ClassNode;

import cuchaz.enigma.classprovider.ClassProvider;
import cuchaz.enigma.source.Decompiler;
import cuchaz.enigma.source.Source;
import cuchaz.enigma.source.SourceSettings;
import cuchaz.enigma.translation.mapping.EntryRemapper;

public class TokenizingDisassembler implements Decompiler {
	private final ClassProvider classProvider;

	public TokenizingDisassembler(ClassProvider classProvider, SourceSettings settings) {
		this.classProvider = classProvider;
	}

	@Override
	public Source getSource(String className, @Nullable EntryRemapper remapper) {
		ClassNode node = classProvider.get(className);
		if (node == null) {
			throw new IllegalStateException("No ClassNode for class '" + className + "' befined by class provided " + classProvider);
		}
		return new TDASource(node, remapper);
	}
}
