package cuchaz.enigma.source.tda;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.checkerframework.checker.nullness.qual.Nullable;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodNode;

import cuchaz.enigma.source.Source;
import cuchaz.enigma.source.SourceIndex;
import cuchaz.enigma.source.tda.UnarySurrogate.UnaryJumpSurrogate;
import cuchaz.enigma.translation.mapping.EntryRemapper;
import cuchaz.enigma.translation.representation.MethodDescriptor;
import cuchaz.enigma.translation.representation.TypeDescriptor;
import cuchaz.enigma.translation.representation.entry.ClassEntry;
import cuchaz.enigma.translation.representation.entry.Entry;
import cuchaz.enigma.translation.representation.entry.FieldEntry;
import cuchaz.enigma.translation.representation.entry.MethodEntry;

class TDASource implements Source {

	private final ClassNode node;

	@Nullable
	private final EntryRemapper remapper;

	public TDASource(ClassNode node, @Nullable EntryRemapper remapper) {
		this.node = node;
		this.remapper = remapper;
	}

	@Override
	public String asString() {
		return index().getSource();
	}

	@Override
	public Source withJavadocs(EntryRemapper remapper) {
		return new TDASource(node, remapper);
	}

	@Override
	public SourceIndex index() {
		StringBuilder builder = new StringBuilder();
		int packageSeperator = node.name.lastIndexOf('/');
		if (packageSeperator != -1) {
			builder.append("package ").append(node.name.substring(0, packageSeperator).replace('/', '.')).append(";\n\n");
		}

		AccessUtil.writeAccessModifiersClass(node.access, builder);
		builder.append(" class ");
		int classNameStart = builder.length();
		String simpleName = node.name.substring(packageSeperator + 1);
		int classNameEnd = simpleName.length() + classNameStart;
		List<Token> tokens = new ArrayList<>();
		builder.append(simpleName);
		tokens.add(new Token(classNameStart, classNameEnd, node.name, null, null));

		if (node.superName != null && !node.superName.equals("java/lang/Object")) {
			String superName = node.superName.replace('/', '.');
			if (superName.startsWith("java.lang.") && superName.lastIndexOf('.') == 9) {
				superName = superName.substring(10);
			}
			classNameStart = classNameEnd + 9;
			classNameEnd = classNameStart + superName.length();
			builder.append(" extends ").append(superName);
			tokens.add(new Token(classNameStart, classNameEnd, node.superName, null, null));
		}

		if (!node.interfaces.isEmpty()) {
			builder.append(" implements ");
			classNameStart = classNameEnd + 12;
			for (String itf : node.interfaces) {
				String fqnItf = itf;
				if (itf.startsWith("java/lang/") && itf.lastIndexOf('/') == 9) {
					itf = itf.substring(10);
				}
				itf = itf.replace('/', '.');
				builder.append(itf).append(", ");
				classNameEnd = classNameStart + itf.length();
				tokens.add(new Token(classNameStart, classNameEnd, fqnItf, null, null));
				classNameStart = classNameEnd + 2;
			}
			builder.setLength(classNameEnd);
		}

		builder.append(" {");

		for (FieldNode field : node.fields) {
			builder.append("\n\t");
			AccessUtil.writeAccessModifiersField(field.access, builder);
			if (field.access != 0) {
				builder.appendCodePoint(' ');
			}
			Type type = Type.getType(field.desc);
			String className = type.getClassName();
			if (field.desc.codePointBefore(field.desc.length()) == ';') {
				if (className.startsWith("java.lang.") && className.lastIndexOf('.') == 9) {
					className = className.substring(10);
				}
				String internalName;
				if (field.desc.codePointAt(0) == '[') {
					internalName = field.desc.substring(type.getDimensions() + 1, field.desc.length() - 1);
				} else {
					internalName = field.desc.substring(1, field.desc.length() - 1);
				}
				tokens.add(new Token(builder.length(), builder.length() + className.length(), internalName, null, null));
			}
			builder.append(className).appendCodePoint(' ');
			int beginFieldName = builder.length();
			builder.append(field.name).append(";");
			tokens.add(new Token(beginFieldName, beginFieldName + field.name.length(), node.name, field.name, field.desc));
		}

		builder.append("\n");
		for (MethodNode method : node.methods) {
			builder.append("\n\t");
			if (!method.name.equals("<clinit>")) {
				AccessUtil.writeAccessModifiersMethod(method.access, builder);
				if (method.access != 0) {
					builder.appendCodePoint(' ');
				}
				int position = builder.length();
				Type methodType = Type.getMethodType(method.desc);
				Type retType = methodType.getReturnType();
				String ret = retType.getClassName();
				String retDesc = retType.getDescriptor();
				if (retDesc.codePointBefore(retDesc.length()) == ';') {
					int adepth = 0;
					if (retDesc.codePointAt(0) == '[') {
						adepth = retType.getDimensions();
					}
					tokens.add(new Token(position, position + ret.length() - 2 * adepth, retDesc.substring(1 + adepth, retDesc.length() - 1), null, null));
				}
				builder.append(ret).append(' ').append(method.name).append('(');
				position += ret.length() + 1;
				int endPos = position + method.name.length();
				tokens.add(new Token(position, endPos, node.name, method.name, method.desc));
				position = endPos + 1;

				int localIndex = ((method.access & Opcodes.ACC_STATIC) == 0) ? 1 : 0;
				boolean hasArgs = false;

				for (Type arg : methodType.getArgumentTypes()) {
					hasArgs = true;
					String argStr = arg.getClassName();
					String argDesc = arg.getDescriptor();

					if (argDesc.codePointBefore(argDesc.length()) == ';') {
						int adepth = 0;
						if (argDesc.codePointAt(0) == '[') {
							adepth = arg.getDimensions();
						}
						tokens.add(new Token(position, position + argStr.length() - 2 * adepth, argDesc.substring(1 + adepth, argDesc.length() - 1), null, null));
					}

					String localName = " local" + localIndex + ',';
					builder.append(argStr).append(localName);
					localIndex += arg.getSize();
					position += argStr.length() + localName.length();
				}

				if (hasArgs) {
					position--;
					builder.setLength(builder.length() - 1);
				}

				if ((method.access & Opcodes.ACC_ABSTRACT) != 0) {
					builder.append(");\n");
					continue;
				}
				builder.append(") ");
			}
			builder.append("{\n\t");
			List<InstructionSurrogate> instructions = new LinkedList<>();
			for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
				if (insn.getOpcode() == -1 && insn.getType() != AbstractInsnNode.LABEL) {
					continue;
				}
				instructions.add(UnarySurrogate.surrogateOf(insn));
			}
			Map<LabelNode, LabelSurrogate> labelSurrogates = new HashMap<>();
			for (InstructionSurrogate surrogate : instructions) {
				if (surrogate instanceof LabelSurrogate label) {
					labelSurrogates.put(label.insn, label);
				}
			}
			for (InstructionSurrogate surrogate : instructions) {
				if (surrogate instanceof UnaryJumpSurrogate jump) {
					LabelSurrogate label = labelSurrogates.get(jump.insn.label);
					jump.link(label);
					label.backreferences.add(jump);
				}
			}
			Iterator<InstructionSurrogate> it = instructions.iterator();
			int labelCounter = 0;
			while (it.hasNext()) {
				if (it.next() instanceof LabelSurrogate label) {
					if (label.backreferences.isEmpty()) {
						it.remove();
					} else {
						label.setName("label" + labelCounter++);
					}
				}
			}
			int position = builder.length();
			for (InstructionSurrogate surrogate : instructions) {
				if (!(surrogate instanceof LabelSurrogate)) {
					builder.appendCodePoint('\t');
					position++;
				}
				position = surrogate.write(builder, tokens, position) + 2;
				builder.append("\n\t");
			}
			builder.append("}\n");
		}

		builder.append("}\n");
		SourceIndex index = new SourceIndex(builder.toString());

		for (Token token : tokens) {
			Entry<?> entry;
			if (token.memberDesc == null) {
				entry = new ClassEntry(token.fqnClass);
			} else if (token.memberDesc.codePointAt(0) == '(') {
				if (token.memberName.equals("<init>")) {
					continue; // Don't allow constructors to be remapped
				}
				entry = new MethodEntry(new ClassEntry(token.fqnClass), token.memberName, new MethodDescriptor(token.memberDesc));
			} else {
				entry = new FieldEntry(new ClassEntry(token.fqnClass), token.memberName, new TypeDescriptor(token.memberDesc));
			}
			index.addDeclaration(new cuchaz.enigma.source.Token(token.start, token.end, builder.substring(token.start, token.end)), entry);
		}
		return index;
	}
}
