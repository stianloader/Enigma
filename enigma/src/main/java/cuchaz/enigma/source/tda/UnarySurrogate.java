package cuchaz.enigma.source.tda;

import java.util.Collection;
import java.util.Locale;
import java.util.Objects;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

public class UnarySurrogate<T extends AbstractInsnNode> implements InstructionSurrogate {

	public final T insn;

	public UnarySurrogate(T insn) {
		this.insn = insn;
	}

	@Override
	public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
		String str = Integer.toHexString(insn.getOpcode()) + ":" + this.insn.toString();
		outString.append(str);
		return startIndex + str.length();
	}

	@Override
	public boolean allowInline() {
		return false;
	}

	public static class SimpleUnarySurrogate extends UnarySurrogate<InsnNode> {
		protected final String insnName;

		public SimpleUnarySurrogate(InsnNode insn, String name) {
			super(insn);
			this.insnName = name;
		}

		@Override
		public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
			outString.append(insnName);
			return startIndex + insnName.length();
		}
	}

	public static class UnaryArraySurrogate extends SimpleUnarySurrogate {
		public UnaryArraySurrogate(InsnNode insn, String name) {
			super(insn, name);
		}

		public boolean isStoring() {
			return insnName.length() == 7;
		}
	}

	public static class UnaryIINCSurrogate extends UnarySurrogate<IincInsnNode> {

		public UnaryIINCSurrogate(IincInsnNode insn) {
			super(insn);
		}

		@Override
		public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
			String index = Integer.toString(insn.var);
			String amount = (insn.incr < 0 ? "" : "+") + insn.incr;
			outString.append("IINC ").append(index).appendCodePoint(' ').append(amount);
			return startIndex + index.length() + amount.length() + 6;
		}
	}

	public static class UnaryVarSurrogate extends UnarySurrogate<VarInsnNode> {

		private final String insnName;

		public UnaryVarSurrogate(VarInsnNode insn, String name) {
			super(insn);
			this.insnName = name;
		}

		@Override
		public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
			outString.append(insnName);
			String index = Integer.toString(insn.var);
			outString.appendCodePoint(' ').append(index);
			return startIndex + insnName.length() + index.length() + 1;
		}

		public boolean isStoring() {
			return insnName.length() == 6;
		}
	}

	public static class UnaryTypeSurrogate extends UnarySurrogate<TypeInsnNode> {
		private final String insnString;

		public UnaryTypeSurrogate(TypeInsnNode insn, String insnString) {
			super(insn);
			this.insnString = insnString;
		}

		@Override
		public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
			outString.append(insnString)
				.appendCodePoint(' ')
				.append(insn.desc);
			int classNameBegin = startIndex + insnString.length() + 1;
			int classNameEnd = classNameBegin + insn.desc.length();
			String className = insn.desc;
			if (insn.desc.codePointBefore(insn.desc.length()) == ';') {
				classNameEnd--;
				classNameBegin++;
				int i;
				for (i = 0; insn.desc.codePointAt(i) == '['; i++) {
					classNameBegin++;
				}
				className = className.substring(i + 1, className.length() - 1);
			}
			tokenOut.add(new Token(classNameBegin, classNameEnd, className, null, null));
			return startIndex + insn.desc.length() + insnString.length() + 1;
		}
	}

	public static class UnaryConstantSurrogate<T extends AbstractInsnNode> extends UnarySurrogate<T> {
		private final String insnString;
		private final String constantValue;

		public UnaryConstantSurrogate(T insn, String insnString, String constantValue) {
			super(insn);
			this.insnString = insnString;
			this.constantValue = constantValue;
		}

		@Override
		public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
			outString.append(insnString);
			return startIndex + insnString.length();
		}

		public String getConstantAsString() {
			return constantValue;
		}
	}

	public static class UnaryFieldSurrogate extends UnarySurrogate<FieldInsnNode> {
		private final String insnString;

		public UnaryFieldSurrogate(FieldInsnNode insn, String insnString) {
			super(insn);
			this.insnString = insnString;
		}

		@Override
		public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
			outString.append(insnString)
				.appendCodePoint(' ')
				.append(insn.owner)
				.appendCodePoint('.')
				.append(insn.name)
				.appendCodePoint(' ')
				.append(insn.desc);
			int classNameBegin = startIndex + insnString.length() + 1;
			int classNameEnd = classNameBegin + insn.owner.length();
			int fieldNameBegin = classNameEnd + 1;
			int fieldNameEnd = fieldNameBegin + insn.name.length();
			tokenOut.add(new Token(classNameBegin, classNameEnd, insn.owner, null, null));
			tokenOut.add(new Token(fieldNameBegin, fieldNameEnd, insn.owner, insn.name, insn.desc));
			return fieldNameEnd + insn.desc.length() + 1;
		}
	}

	public static class UnaryNewArraySurrogate extends UnarySurrogate<IntInsnNode> {

		public UnaryNewArraySurrogate(IntInsnNode insn) {
			super(insn);
		}

		@Override
		public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
			outString.append("NEWARRAY ").append(getArrayType());
			return startIndex + 10;
		}

		public char getArrayType() {
			// Apparently these magic values are hardcoded without much more info or other documentation
			// The order makes absolutely no sense too
			switch (insn.operand) {
			case 4:
				return 'Z';
			case 5:
				return 'C';
			case 6:
				return 'F';
			case 7:
				return 'D';
			case 8:
				return 'B';
			case 9:
				return 'S';
			case 10:
				return 'I';
			case 11:
				return 'J';
			default:
				throw new IllegalStateException("Unknown descriptor: " + insn.operand);
			}
		}
	}

	public static class UnaryMethodSurrogate extends UnarySurrogate<MethodInsnNode> {
		private final String insnString;

		public UnaryMethodSurrogate(MethodInsnNode insn, String insnString) {
			super(insn);
			this.insnString = insnString;
		}

		@Override
		public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
			outString.append(insnString)
				.appendCodePoint(' ')
				.append(insn.owner)
				.appendCodePoint('.')
				.append(insn.name)
				.append(insn.desc);
			int classNameBegin = startIndex + insnString.length() + 1;
			int classNameEnd = classNameBegin + insn.owner.length();
			int methodNameBegin = classNameEnd + 1;
			int methodNameEnd = methodNameBegin + insn.name.length();
			tokenOut.add(new Token(classNameBegin, classNameEnd, insn.owner, null, null));
			tokenOut.add(new Token(methodNameBegin, methodNameEnd, insn.owner, insn.name, insn.desc));
			return methodNameEnd + insn.desc.length();
		}
	}

	public static class UnaryReturnSurrogate extends SimpleUnarySurrogate {
		public UnaryReturnSurrogate(InsnNode insn, String insnString) {
			super(insn, insnString);
		}
	}

	public static class UnaryJumpSurrogate extends UnarySurrogate<JumpInsnNode> {
		private final String insnString;
		private LabelSurrogate linked;

		public UnaryJumpSurrogate(JumpInsnNode insn, String insnString) {
			super(insn);
			this.insnString = insnString;
		}

		public void link(LabelSurrogate linked) {
			this.linked = Objects.requireNonNull(linked, "linked may not be null");
		}

		@Override
		public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
			if (linked == null) {
				throw new IllegalStateException("Jump surrogate not linked to a label surrogate");
			}
			String labelName = linked.getName();
			outString.append(insnString).appendCodePoint(' ').append(labelName);
			return startIndex + insnString.length() + labelName.length() + 1;
		}
	}

	@SuppressWarnings("unchecked") // It is checked - I hope.
	public static <T extends AbstractInsnNode> UnarySurrogate<T> surrogateOf(T insn) {
		switch (insn.getOpcode()) {
		case Opcodes.AALOAD:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "AALOAD");
		case Opcodes.BALOAD:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "BALOAD");
		case Opcodes.CALOAD:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "CALOAD");
		case Opcodes.DALOAD:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "DALOAD");
		case Opcodes.FALOAD:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "FALOAD");
		case Opcodes.IALOAD:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "IALOAD");
		case Opcodes.LALOAD:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "LALOAD");
		case Opcodes.SALOAD:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "SALOAD");
		case Opcodes.ALOAD:
			return (UnarySurrogate<T>) new UnaryVarSurrogate((VarInsnNode) insn, "ALOAD");
		case Opcodes.DLOAD:
			return (UnarySurrogate<T>) new UnaryVarSurrogate((VarInsnNode) insn, "DLOAD");
		case Opcodes.FLOAD:
			return (UnarySurrogate<T>) new UnaryVarSurrogate((VarInsnNode) insn, "FLOAD");
		case Opcodes.ILOAD:
			return (UnarySurrogate<T>) new UnaryVarSurrogate((VarInsnNode) insn, "ILOAD");
		case Opcodes.LLOAD:
			return (UnarySurrogate<T>) new UnaryVarSurrogate((VarInsnNode) insn, "LLOAD");
		case Opcodes.AASTORE:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "AASTORE");
		case Opcodes.BASTORE:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "BASTORE");
		case Opcodes.CASTORE:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "CASTORE");
		case Opcodes.DASTORE:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "DASTORE");
		case Opcodes.FASTORE:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "FASTORE");
		case Opcodes.IASTORE:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "IASTORE");
		case Opcodes.LASTORE:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "LASTORE");
		case Opcodes.SASTORE:
			return (UnarySurrogate<T>) new UnaryArraySurrogate((InsnNode) insn, "SASTORE");
		case Opcodes.ASTORE:
			return (UnarySurrogate<T>) new UnaryVarSurrogate((VarInsnNode) insn, "ASTORE");
		case Opcodes.DSTORE:
			return (UnarySurrogate<T>) new UnaryVarSurrogate((VarInsnNode) insn, "DSTORE");
		case Opcodes.FSTORE:
			return (UnarySurrogate<T>) new UnaryVarSurrogate((VarInsnNode) insn, "FSTORE");
		case Opcodes.ISTORE:
			return (UnarySurrogate<T>) new UnaryVarSurrogate((VarInsnNode) insn, "ISTORE");
		case Opcodes.LSTORE:
			return (UnarySurrogate<T>) new UnaryVarSurrogate((VarInsnNode) insn, "LSTORE");
		case Opcodes.NOP:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "NOP");
		case Opcodes.ICONST_M1:
			return new UnaryConstantSurrogate<>(insn, "ICONST_M1", "-1");
		case Opcodes.ICONST_0:
			return new UnaryConstantSurrogate<>(insn, "ICONST_0", "0");
		case Opcodes.ICONST_1:
			return new UnaryConstantSurrogate<>(insn, "ICONST_1", "1");
		case Opcodes.ICONST_2:
			return new UnaryConstantSurrogate<>(insn, "ICONST_2", "2");
		case Opcodes.ICONST_3:
			return new UnaryConstantSurrogate<>(insn, "ICONST_3", "3");
		case Opcodes.ICONST_4:
			return new UnaryConstantSurrogate<>(insn, "ICONST_4", "4");
		case Opcodes.ICONST_5:
			return new UnaryConstantSurrogate<>(insn, "ICONST_5", "5");
		case Opcodes.FCONST_0:
			return new UnaryConstantSurrogate<>(insn, "FCONST_0", "0F");
		case Opcodes.FCONST_1:
			return new UnaryConstantSurrogate<>(insn, "FCONST_1", "1F");
		case Opcodes.FCONST_2:
			return new UnaryConstantSurrogate<>(insn, "FCONST_2", "2F");
		case Opcodes.DCONST_0:
			return new UnaryConstantSurrogate<>(insn, "DCONST_0", "0D");
		case Opcodes.DCONST_1:
			return new UnaryConstantSurrogate<>(insn, "DCONST_1", "1D");
		case Opcodes.LCONST_0:
			return new UnaryConstantSurrogate<>(insn, "LCONST_0", "0L");
		case Opcodes.LCONST_1:
			return new UnaryConstantSurrogate<>(insn, "LCONST_1", "1L");
		case Opcodes.ACONST_NULL:
			return new UnaryConstantSurrogate<>(insn, "ACONST_NULL", "null");
		case Opcodes.BIPUSH: {
			String operand = Integer.toString(((IntInsnNode) insn).operand);
			return new UnaryConstantSurrogate<>(insn, "BIPUSH " + operand, operand);
		}
		case Opcodes.SIPUSH: {
			String operand = Integer.toString(((IntInsnNode) insn).operand);
			return new UnaryConstantSurrogate<>(insn, "SIPUSH " + operand, operand);
		}
		case Opcodes.LDC: {
			LdcInsnNode ldcInsn = (LdcInsnNode) insn;
			String operand;
			if (ldcInsn.cst instanceof Double) {
				operand = ((Double) ldcInsn.cst).doubleValue() + "D";
			} else if (ldcInsn.cst instanceof Float) {
				operand = ((Float) ldcInsn.cst).floatValue() + "F";
			} else if (ldcInsn.cst instanceof Integer) {
				operand = ((Integer) ldcInsn.cst).toString();
			} else if (ldcInsn.cst instanceof Long) {
				operand = ((Long) ldcInsn.cst).longValue() + "L";
			} else if (ldcInsn.cst instanceof String) {
				operand = '"' + ((String) ldcInsn.cst).replace("\\", "\\\\").replace("\n", "\\n").replace("\"", "\\\"") + '"';
			} else if (ldcInsn.cst instanceof Type type) {
				if (type.getSort() == Type.METHOD) {
					return new UnarySurrogate<>(insn) {
						@Override
						public int write(StringBuilder outString, Collection<Token> tokenOut, int startIndex) {
							outString.append("LDC ");
							String methodDesc = type.getDescriptor();
							outString.append(methodDesc);
							return startIndex + 4 + methodDesc.length();
						}
					};
				}
				return new UnaryConstantSurrogate<>(insn, "LDC " + type.getDescriptor(), type.getClassName() + ".class");
			} else {
				return new UnarySurrogate<>(insn);
			}
			return new UnaryConstantSurrogate<>(insn, "LDC " + operand, operand);
		}
		case Opcodes.PUTFIELD:
			return (UnarySurrogate<T>) new UnaryFieldSurrogate((FieldInsnNode) insn, "PUTFIELD");
		case Opcodes.PUTSTATIC:
			return (UnarySurrogate<T>) new UnaryFieldSurrogate((FieldInsnNode) insn, "PUTSTATIC");
		case Opcodes.GETFIELD:
			return (UnarySurrogate<T>) new UnaryFieldSurrogate((FieldInsnNode) insn, "GETFIELD");
		case Opcodes.GETSTATIC:
			return (UnarySurrogate<T>) new UnaryFieldSurrogate((FieldInsnNode) insn, "GETSTATIC");
		case Opcodes.INVOKEVIRTUAL:
			return (UnarySurrogate<T>) new UnaryMethodSurrogate((MethodInsnNode) insn, "INVOKEVIRTUAL");
		case Opcodes.INVOKESTATIC:
			return (UnarySurrogate<T>) new UnaryMethodSurrogate((MethodInsnNode) insn, "INVOKESTATIC");
		case Opcodes.INVOKEINTERFACE:
			return (UnarySurrogate<T>) new UnaryMethodSurrogate((MethodInsnNode) insn, "INVOKEINTERFACE");
		case Opcodes.INVOKESPECIAL:
			return (UnarySurrogate<T>) new UnaryMethodSurrogate((MethodInsnNode) insn, "INVOKESPECIAL");
		case Opcodes.ATHROW:
			return (UnarySurrogate<T>) new UnaryReturnSurrogate((InsnNode) insn, "ATHROW");
		case Opcodes.RETURN:
			return (UnarySurrogate<T>) new UnaryReturnSurrogate((InsnNode) insn, "RETURN");
		case Opcodes.ARETURN:
			return (UnarySurrogate<T>) new UnaryReturnSurrogate((InsnNode) insn, "ARETURN");
		case Opcodes.DRETURN:
			return (UnarySurrogate<T>) new UnaryReturnSurrogate((InsnNode) insn, "DRETURN");
		case Opcodes.FRETURN:
			return (UnarySurrogate<T>) new UnaryReturnSurrogate((InsnNode) insn, "FRETURN");
		case Opcodes.IRETURN:
			return (UnarySurrogate<T>) new UnaryReturnSurrogate((InsnNode) insn, "IRETURN");
		case Opcodes.LRETURN:
			return (UnarySurrogate<T>) new UnaryReturnSurrogate((InsnNode) insn, "LRETURN");
		case Opcodes.IREM:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "IREM");
		case Opcodes.ISUB:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "ISUB");
		case Opcodes.IADD:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "IADD");
		case Opcodes.IDIV:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "IDIV");
		case Opcodes.IOR:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "IOR");
		case Opcodes.IXOR:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "IXOR");
		case Opcodes.ISHL:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "ISHL");
		case Opcodes.ISHR:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "ISHR");
		case Opcodes.IUSHR:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "IUSHR");
		case Opcodes.IMUL:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "IMUL");
		case Opcodes.LREM:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LREM");
		case Opcodes.LSUB:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LSUB");
		case Opcodes.LADD:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LADD");
		case Opcodes.LDIV:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LDIV");
		case Opcodes.LOR:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LOR");
		case Opcodes.LXOR:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LXOR");
		case Opcodes.LSHL:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LSHL");
		case Opcodes.LSHR:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LSHR");
		case Opcodes.LUSHR:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LUSHR");
		case Opcodes.LMUL:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LMUL");
		case Opcodes.FREM:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "FREM");
		case Opcodes.FSUB:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "FSUB");
		case Opcodes.FADD:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "FADD");
		case Opcodes.FDIV:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "FDIV");
		case Opcodes.FMUL:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "FMUL");
		case Opcodes.DREM:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DREM");
		case Opcodes.DSUB:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DSUB");
		case Opcodes.DADD:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DADD");
		case Opcodes.DDIV:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DDIV");
		case Opcodes.DMUL:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DMUL");
		case Opcodes.DNEG:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DNEG");
		case Opcodes.FNEG:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "FNEG");
		case Opcodes.INEG:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "INEG");
		case Opcodes.LNEG:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LNEG");
		case Opcodes.DUP:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DUP");
		case Opcodes.DUP_X1:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DUP_X1");
		case Opcodes.DUP_X2:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DUP_X2");
		case Opcodes.DUP2_X1:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DUP2_X1");
		case Opcodes.DUP2_X2:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DUP2_X2");
		case Opcodes.POP:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "POP");
		case Opcodes.POP2:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "POP2");
		case Opcodes.SWAP:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "SWAP");
		case Opcodes.GOTO:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "GOTO");
		case Opcodes.IF_ACMPEQ:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IF_ACMPEQ");
		case Opcodes.IF_ACMPNE:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IF_ACMPNE");
		case Opcodes.IF_ICMPEQ:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IF_ICMPEQ");
		case Opcodes.IF_ICMPGE:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IF_ICMPGE");
		case Opcodes.IF_ICMPGT:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IF_ICMPGT");
		case Opcodes.IF_ICMPLE:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IF_ICMPLE");
		case Opcodes.IF_ICMPLT:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IF_ICMPLT");
		case Opcodes.IF_ICMPNE:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IF_ICMPNE");
		case Opcodes.IFEQ:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IFEQ");
		case Opcodes.IFGE:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IFGE");
		case Opcodes.IFGT:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IFGT");
		case Opcodes.IFLE:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IFLE");
		case Opcodes.IFLT:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IFLT");
		case Opcodes.IFNE:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IFNE");
		case Opcodes.IFNONNULL:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IFNONNULL");
		case Opcodes.IFNULL:
			return (UnarySurrogate<T>) new UnaryJumpSurrogate((JumpInsnNode) insn, "IFNULL");
		case Opcodes.FCMPG:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "FCMP");
		case Opcodes.FCMPL:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "FCMPL");
		case Opcodes.LCMP:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "LCMP");
		case Opcodes.DCMPG:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DCMPG");
		case Opcodes.DCMPL:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "DCMPL");
		case Opcodes.I2B:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "I2B");
		case Opcodes.I2C:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "I2C");
		case Opcodes.I2D:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "I2D");
		case Opcodes.I2F:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "I2F");
		case Opcodes.I2L:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "I2L");
		case Opcodes.I2S:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "I2S");
		case Opcodes.L2D:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "L2D");
		case Opcodes.L2F:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "L2F");
		case Opcodes.L2I:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "L2I");
		case Opcodes.D2L:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "D2L");
		case Opcodes.D2F:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "D2F");
		case Opcodes.D2I:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "D2I");
		case Opcodes.F2L:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "F2L");
		case Opcodes.F2D:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "F2D");
		case Opcodes.F2I:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "F2I");
		case Opcodes.ARRAYLENGTH:
			return (UnarySurrogate<T>) new SimpleUnarySurrogate((InsnNode) insn, "ARRAYLENGTH");
		case Opcodes.NEW:
			return (UnarySurrogate<T>) new UnaryTypeSurrogate((TypeInsnNode) insn, "NEW");
		case Opcodes.ANEWARRAY:
			return (UnarySurrogate<T>) new UnaryTypeSurrogate((TypeInsnNode) insn, "ANEWARRAY");
		case Opcodes.CHECKCAST:
			return (UnarySurrogate<T>) new UnaryTypeSurrogate((TypeInsnNode) insn, "CHECKCAST");
		case Opcodes.INSTANCEOF:
			return (UnarySurrogate<T>) new UnaryTypeSurrogate((TypeInsnNode) insn, "INSTANCEOF");
		case Opcodes.IINC:
			return (UnarySurrogate<T>) new UnaryIINCSurrogate((IincInsnNode) insn);
		case Opcodes.NEWARRAY:
			return (UnarySurrogate<T>) new UnaryNewArraySurrogate((IntInsnNode) insn);
		case Opcodes.TABLESWITCH:
			// We probably don't want to display tableswitches as a giant one-liner.
			// As such we will resugar the tableswitch later on in the pipeline instead.
			return new UnarySurrogate<>(insn);
		case Opcodes.LOOKUPSWITCH:
			return new UnarySurrogate<>(insn);
		case Opcodes.INVOKEDYNAMIC:
			// Similarly, Indys are sugared into two instructions
			return new UnarySurrogate<>(insn);
		case -1:
			if (insn instanceof LabelNode label) {
				return (UnarySurrogate<T>) new LabelSurrogate(label);
			}
			return new UnarySurrogate<>(insn);
		default:
			System.err.println("Unknown opcode: " + insn.getOpcode() + "(" + Integer.toHexString(insn.getOpcode()).toUpperCase(Locale.ROOT) + "); " + insn.getClass().toString());
			return new UnarySurrogate<>(insn);
		}
	}
}
