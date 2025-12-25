# 🚀 **JX Language: Systems Programming Language for OS Development**

**JX** is a low-level systems programming language specifically designed for building operating systems and kernels. It provides modern programming experience while maintaining direct hardware control.

## ✨ **Core Features:**

### 🔧 **Direct Hardware Control**
- Direct register access
- Inline assembly instructions
- Interrupt handling
- Manual memory management

### ⚡ **Direct Machine Code Generation**
- No intermediate compiler needed (like GCC)
- Direct binary output
- Multiboot header support
- Bootable kernel generation

### 🧠 **Modern Syntax with System Focus**
- Clean, readable syntax
- Static typing
- Zero-cost abstractions
- No runtime overhead
- No garbage collector

### 🛡️ **Memory Safety Options**
- Optional bounds checking
- Pointer arithmetic control
- Manual allocation/deallocation
- Stack/heap management

## 📚 **Language Overview:**

### **Basic Syntax:**
```jx
// Kernel entry point
kernel main {
    // Disable interrupts
    cli;
    
    // Hardware I/O
    let port: u16 = 0x3F8;
    let data: u8 = 0x41;
    out(port, data);
    
    // Infinite loop
    loop {
        hlt;
    }
}
```

### **Type System:**
- **Primitive Types:** u8, u16, u32, u64, i8, i16, i32, i64, f32, f64, bool
- **Pointer Types:** *T (raw pointers)
- **Function Types:** fn(args) -> return_type
- **Structs & Enums** for data organization

### **Hardware Access:**
```jx
// Inline assembly
asm("mov rax, 0xB8000");
asm("mov byte [rax], 'A'");

// CPU instructions
cli;    // Clear interrupt flag
sti;    // Set interrupt flag
hlt;    // Halt CPU
nop;    // No operation

// I/O operations
in(port);       // Read from port
out(port, val); // Write to port
```

## 🎯 **Target Audience:**
- OS developers
- Kernel programmers
- Embedded systems engineers
- Compiler developers
- Educational OS projects

## 🚀 **Getting Started:**

### **1. Compile a Kernel:**
```bash
# Clone the compiler
git clone https://github.com/gmene009-art/jx-lang.git

# Compile your kernel
cd jx-lang
./jx your_kernel.jx -o kernel.bin

# Run in QEMU
qemu-system-x86_64 -kernel kernel.bin
```

### **2. Simple Kernel Example:**
```jx
// hello.jx
kernel main {
    // Initialize VGA text mode
    let vga: *u16 = 0xB8000;
    
    // Print "JX"
    vga[0] = ('J' | 0x0F00);
    vga[1] = ('X' | 0x0F00);
    
    // Halt
    loop {
        hlt;
    }
}
```

## 🔧 **Compiler Architecture:**
- **Lexer:** Tokenizes source code
- **Parser:** Builds Abstract Syntax Tree (AST)
- **Type Checker:** Validates types
- **Code Generator:** Produces x86-64 machine code
- **Linker:** Creates bootable binary

## 🌟 **Why JX?**

### **Advantages over alternatives:**
- ✅ **Lighter than C++/Rust** for kernel development
- ✅ **More control than C** with modern features
- ✅ **No external dependencies** for code generation
- ✅ **Designed specifically** for systems programming
- ✅ **Direct binary output** without assembler

## 📦 **Project Status:**
- ✅ **Working compiler** (C implementation)
- ✅ **Basic language features**
- ✅ **Kernel generation**
- ✅ **Multiboot support**
- 🔄 **Active development**
- 🔄 **Community contributions welcome**

## 🤝 **Call to Developers:**

We invite all developers to:
1. **Improve the language** - Add new features
2. **Fix bugs** - Report and resolve issues
3. **Use it** - Build your own OS/kernel
4. **Share feedback** - Help shape the language
5. **Contribute** - Submit pull requests

## 🔗 **Resources:**
- **GitHub:** [Repository Link]
- **Documentation:** [Docs Link]
- **Examples:** [Examples Directory]
- **Community:** [Discord/Forum Link]

## 📄 **License:**
Apache License 2.0 - Open for commercial and personal use.

---

**Join us in building the future of systems programming!** 🚀

*JX: Because your kernel deserves a language that speaks its language.*
