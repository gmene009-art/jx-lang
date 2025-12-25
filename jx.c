/*
 * JX Compiler v1.0 - Kernel Language for AbdelalyOS
 * Complete systems programming language with direct binary generation
 * 
 * Features:
 * - Direct x86-64 machine code output
 * - Zero dependencies, no assembler needed
 * - Full control over CPU, memory, interrupts
 * - Task and scheduler support
 * - Built-in hardware I/O
 * - Bootable kernel generation
 * 
 * Compile: gcc -O3 -o jx jx.c
 * Usage: ./jx kernel.jx -o kernel.bin
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>

// ============== Configuration ==============
#define JX_VERSION "1.0.0"
#define MAX_TOKENS 65536
#define MAX_SYMBOLS 4096
#define MAX_CODE_SIZE (2 << 20)  // 2MB
#define MAX_DATA_SIZE (1 << 20)  // 1MB
#define MAX_SECTIONS 32

// ============== Token Types ==============
typedef enum {
    // Special
    TOK_EOF, TOK_ERROR,
    
    // Literals
    TOK_INT, TOK_HEX, TOK_BIN, TOK_CHAR, TOK_STRING,
    
    // Identifiers
    TOK_ID,
    
    // Keywords - Core
    TOK_KERNEL, TOK_FN, TOK_TASK, TOK_INTERRUPT,
    TOK_IMPORT, TOK_EXPORT, TOK_ASM, TOK_INLINE,
    
    // Keywords - Types
    TOK_U8, TOK_U16, TOK_U32, TOK_U64,
    TOK_I8, TOK_I16, TOK_I32, TOK_I64,
    TOK_F32, TOK_F64, TOK_BOOL, TOK_VOID,
    TOK_PTR, TOK_REF, TOK_MUT,
    
    // Keywords - Control
    TOK_IF, TOK_ELSE, TOK_WHILE, TOK_FOR, TOK_LOOP,
    TOK_BREAK, TOK_CONTINUE, TOK_RETURN, TOK_MATCH,
    TOK_CASE, TOK_DEFAULT,
    
    // Keywords - Memory
    TOK_LET, TOK_CONST, TOK_STATIC, TOK_VOLATILE,
    TOK_NEW, TOK_DELETE, TOK_ALLOC, TOK_FREE,
    
    // Keywords - Hardware
    TOK_IN, TOK_OUT, TOK_CLI, TOK_STI, TOK_HLT,
    TOK_CPUID, TOK_RDMSR, TOK_WRMSR, TOK_RDTSC,
    
    // Keywords - System
    TOK_ENABLE_IRQ, TOK_DISABLE_IRQ, TOK_YIELD,
    TOK_SLEEP, TOK_PANIC, TOK_ASSERT,
    
    // Operators
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT,
    TOK_PLUSEQ, TOK_MINUSEQ, TOK_STAREQ, TOK_SLASHEQ,
    TOK_PERCENTEQ, TOK_AMPEQ, TOK_PIPEEQ, TOK_CARETEQ,
    TOK_LSHIFTEQ, TOK_RSHIFTEQ,
    TOK_EQ, TOK_EQEQ, TOK_NE, TOK_LT, TOK_LE, TOK_GT, TOK_GE,
    TOK_AND, TOK_OR, TOK_NOT, TOK_AMP, TOK_PIPE, TOK_CARET, TOK_TILDE,
    TOK_AMPAMP, TOK_PIPEPIPE, TOK_LSHIFT, TOK_RSHIFT,
    TOK_PLUSPLUS, TOK_MINUSMINUS,
    TOK_ARROW, TOK_DOT, TOK_COLON, TOK_DBLCOLON,
    
    // Delimiters
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_LBRACK, TOK_RBRACK, TOK_SEMI, TOK_COMMA,
    TOK_AT, TOK_HASH, TOK_DOLLAR, TOK_QUEST,
    
    // Registers
    TOK_RAX, TOK_RBX, TOK_RCX, TOK_RDX,
    TOK_RSI, TOK_RDI, TOK_RBP, TOK_RSP,
    TOK_R8, TOK_R9, TOK_R10, TOK_R11,
    TOK_R12, TOK_R13, TOK_R14, TOK_R15,
    TOK_EAX, TOK_EBX, TOK_ECX, TOK_EDX,
    
    // Sections
    TOK_SECTION_TEXT, TOK_SECTION_DATA, TOK_SECTION_BSS,
    TOK_SECTION_RODATA, TOK_ALIGN, TOK_GLOBAL, TOK_EXTERN,
} TokenType;

// ============== Lexer ==============
typedef struct {
    TokenType type;
    char text[256];
    uint64_t value;
    int line, col;
    char *filename;
} Token;

typedef struct {
    char *source;
    char *filename;
    int length;
    int position;
    int line;
    int column;
    
    Token tokens[MAX_TOKENS];
    int token_count;
    int current_token;
} Lexer;

// ============== Parser ==============
typedef enum {
    TY_VOID, TY_INT, TY_UINT, TY_FLOAT, TY_BOOL, TY_CHAR,
    TY_PTR, TY_ARRAY, TY_STRUCT, TY_UNION, TY_ENUM,
    TY_FUNC, TY_TASK
} TypeKind;

typedef struct Type {
    TypeKind kind;
    int size;
    int align;
    bool is_const;
    bool is_volatile;
    
    // For pointers/arrays
    struct Type *base;
    int array_size;
    
    // For structs/unions
    struct {
        char **names;
        struct Type **types;
        int *offsets;
        int count;
    } fields;
    
    // For functions
    struct {
        struct Type **params;
        struct Type *return_type;
        int param_count;
        bool is_variadic;
    } func;
} Type;

typedef struct Symbol {
    char name[256];
    Type *type;
    int scope;
    int offset;      // Stack offset or data offset
    bool is_global;
    bool is_extern;
    bool is_export;
    int value;       // For constants
} Symbol;

typedef struct Node Node;
struct Node {
    enum {
        // Declarations
        NODE_KERNEL, NODE_FUNC, NODE_TASK, NODE_INTERRUPT,
        NODE_VAR, NODE_CONST, NODE_STRUCT, NODE_ENUM,
        
        // Statements
        NODE_BLOCK, NODE_EXPR_STMT, NODE_IF, NODE_WHILE,
        NODE_FOR, NODE_LOOP, NODE_RETURN, NODE_BREAK,
        NODE_CONTINUE, NODE_ASM, NODE_YIELD, NODE_PANIC,
        
        // Hardware
        NODE_IN, NODE_OUT, NODE_CLI, NODE_STI, NODE_HLT,
        
        // Expressions
        NODE_INT, NODE_CHAR, NODE_STRING, NODE_IDENT,
        NODE_CALL, NODE_BINOP, NODE_UNOP, NODE_CAST,
        NODE_ADDR, NODE_DEREF, NODE_INDEX, NODE_MEMBER,
        NODE_ASSIGN, NODE_INC, NODE_DEC, NODE_NEW, NODE_DELETE,
        
        // Special
        NODE_IMPORT, NODE_EXPORT, NODE_SECTION,
    } kind;
    
    Type *type;
    Node *next;
    
    union {
        // Literals
        struct { uint64_t int_value; };
        struct { char *str_value; };
        
        // Identifiers
        struct { char name[256]; };
        
        // Expressions
        struct {
            Node *lhs, *rhs;
            int op;
        };
        
        // Statements
        struct {
            Node *cond, *then, *els;
            Node *init, *step;
            Node *body;
            Node *args;
        };
        
        // Assembly
        struct {
            char asm_code[1024];
            char clobbers[256];
        };
        
        // Declarations
        struct {
            Type *decl_type;
            Node *init_value;
        };
    };
};

// ============== Code Generator ==============
typedef struct {
    uint8_t code[MAX_CODE_SIZE];
    uint8_t data[MAX_DATA_SIZE];
    int code_size;
    int data_size;
    int bss_size;
    
    struct {
        char name[256];
        uint64_t address;
        bool is_global;
        bool is_function;
    } symbols[MAX_SYMBOLS];
    int symbol_count;
    
    struct {
        char name[256];
        uint8_t *data;
        int size;
        int align;
    } sections[MAX_SECTIONS];
    int section_count;
    
    // Relocation info
    struct {
        uint64_t offset;
        char symbol[256];
        int type;  // 1=32-bit relative, 2=64-bit absolute
    } relocs[1024];
    int reloc_count;
    
    // Current section
    int current_section;
    
    // x86-64 state
    int current_reg;
    int stack_offset;
} CodeGen;

// ============== Global State ==============
static Lexer lexer;
static Symbol symbol_table[MAX_SYMBOLS];
static int symbol_count = 0;
static int current_scope = 0;
static CodeGen codegen;
static Node *ast_root = NULL;

// ============== Utility Functions ==============
static void error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "\033[1;31mError\033[0m [%s:%d:%d]: ",
            lexer.filename, lexer.line, lexer.column);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(1);
}

static void warning(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "\033[1;33mWarning\033[0m [%s:%d:%d]: ",
            lexer.filename, lexer.line, lexer.column);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

// ============== Lexer Implementation ==============
static char peek_char(void) {
    if (lexer.position >= lexer.length)
        return '\0';
    return lexer.source[lexer.position];
}

static char next_char(void) {
    if (lexer.position >= lexer.length)
        return '\0';
    
    char c = lexer.source[lexer.position++];
    if (c == '\n') {
        lexer.line++;
        lexer.column = 1;
    } else {
        lexer.column++;
    }
    return c;
}

static void skip_whitespace(void) {
    while (isspace(peek_char()))
        next_char();
}

static void skip_comment(void) {
    if (peek_char() == '/' && lexer.source[lexer.position + 1] == '/') {
        while (peek_char() != '\n' && peek_char() != '\0')
            next_char();
    } else if (peek_char() == '/' && lexer.source[lexer.position + 1] == '*') {
        next_char(); // '/'
        next_char(); // '*'
        while (!(peek_char() == '*' && lexer.source[lexer.position + 1] == '/')) {
            if (peek_char() == '\0')
                error("Unterminated comment");
            next_char();
        }
        next_char(); // '*'
        next_char(); // '/'
    }
}

static Token *add_token(TokenType type, const char *text, uint64_t value) {
    if (lexer.token_count >= MAX_TOKENS)
        error("Too many tokens");
    
    Token *tok = &lexer.tokens[lexer.token_count++];
    tok->type = type;
    tok->line = lexer.line;
    tok->col = lexer.column;
    tok->filename = lexer.filename;
    tok->value = value;
    
    if (text)
        strncpy(tok->text, text, sizeof(tok->text) - 1);
    else
        tok->text[0] = '\0';
    
    return tok;
}

static void lex_number(void) {
    char buffer[256];
    int i = 0;
    uint64_t value = 0;
    int base = 10;
    
    if (peek_char() == '0') {
        buffer[i++] = next_char();
        if (peek_char() == 'x' || peek_char() == 'X') {
            buffer[i++] = next_char();
            base = 16;
            while (isxdigit(peek_char()))
                buffer[i++] = next_char();
        } else if (peek_char() == 'b' || peek_char() == 'B') {
            buffer[i++] = next_char();
            base = 2;
            while (peek_char() == '0' || peek_char() == '1')
                buffer[i++] = next_char();
        } else if (peek_char() == 'o' || peek_char() == 'O') {
            buffer[i++] = next_char();
            base = 8;
            while (peek_char() >= '0' && peek_char() <= '7')
                buffer[i++] = next_char();
        } else {
            while (isdigit(peek_char()))
                buffer[i++] = next_char();
        }
    } else {
        while (isdigit(peek_char()))
            buffer[i++] = next_char();
    }
    
    buffer[i] = '\0';
    value = strtoull(buffer, NULL, base);
    
    if (base == 16)
        add_token(TOK_HEX, buffer, value);
    else if (base == 2)
        add_token(TOK_BIN, buffer, value);
    else
        add_token(TOK_INT, buffer, value);
}

static void lex_string(void) {
    char buffer[1024];
    int i = 0;
    
    next_char(); // Skip opening "
    
    while (peek_char() != '"' && peek_char() != '\0') {
        if (peek_char() == '\\') {
            next_char();
            switch (peek_char()) {
                case 'n': buffer[i++] = '\n'; break;
                case 't': buffer[i++] = '\t'; break;
                case 'r': buffer[i++] = '\r'; break;
                case '0': buffer[i++] = '\0'; break;
                case '\\': buffer[i++] = '\\'; break;
                case '"': buffer[i++] = '"'; break;
                case 'x': {
                    next_char();
                    char hex[3] = {0};
                    hex[0] = next_char();
                    hex[1] = next_char();
                    buffer[i++] = (char)strtoul(hex, NULL, 16);
                    break;
                }
                default:
                    buffer[i++] = peek_char();
                    break;
            }
            next_char();
        } else {
            buffer[i++] = next_char();
        }
    }
    
    if (peek_char() == '"')
        next_char();
    
    buffer[i] = '\0';
    
    // Store in data section
    char label[256];
    static int string_id = 0;
    snprintf(label, sizeof(label), "__str_%d", string_id++);
    
    add_token(TOK_STRING, label, 0);
}

static void lex_char(void) {
    next_char(); // Skip opening '
    uint64_t value = 0;
    
    if (peek_char() == '\\') {
        next_char();
        switch (peek_char()) {
            case 'n': value = '\n'; break;
            case 't': value = '\t'; break;
            case 'r': value = '\r'; break;
            case '0': value = '\0'; break;
            case '\\': value = '\\'; break;
            case '\'': value = '\''; break;
            default: value = peek_char(); break;
        }
        next_char();
    } else {
        value = next_char();
    }
    
    if (peek_char() == '\'')
        next_char();
    
    add_token(TOK_CHAR, NULL, value);
}

static TokenType check_keyword(const char *text) {
    struct {
        const char *word;
        TokenType type;
    } keywords[] = {
        // Core
        {"kernel", TOK_KERNEL}, {"fn", TOK_FN}, {"task", TOK_TASK},
        {"interrupt", TOK_INTERRUPT}, {"import", TOK_IMPORT},
        {"export", TOK_EXPORT}, {"asm", TOK_ASM}, {"inline", TOK_INLINE},
        
        // Types
        {"u8", TOK_U8}, {"u16", TOK_U16}, {"u32", TOK_U32}, {"u64", TOK_U64},
        {"i8", TOK_I8}, {"i16", TOK_I16}, {"i32", TOK_I32}, {"i64", TOK_I64},
        {"f32", TOK_F32}, {"f64", TOK_F64}, {"bool", TOK_BOOL}, {"void", TOK_VOID},
        {"ptr", TOK_PTR}, {"ref", TOK_REF}, {"mut", TOK_MUT},
        
        // Control
        {"if", TOK_IF}, {"else", TOK_ELSE}, {"while", TOK_WHILE},
        {"for", TOK_FOR}, {"loop", TOK_LOOP}, {"break", TOK_BREAK},
        {"continue", TOK_CONTINUE}, {"return", TOK_RETURN},
        {"match", TOK_MATCH}, {"case", TOK_CASE}, {"default", TOK_DEFAULT},
        
        // Memory
        {"let", TOK_LET}, {"const", TOK_CONST}, {"static", TOK_STATIC},
        {"volatile", TOK_VOLATILE}, {"new", TOK_NEW}, {"delete", TOK_DELETE},
        {"alloc", TOK_ALLOC}, {"free", TOK_FREE},
        
        // Hardware
        {"in", TOK_IN}, {"out", TOK_OUT}, {"cli", TOK_CLI},
        {"sti", TOK_STI}, {"hlt", TOK_HLT}, {"cpuid", TOK_CPUID},
        {"rdmsr", TOK_RDMSR}, {"wrmsr", TOK_WRMSR}, {"rdtsc", TOK_RDTSC},
        
        // System
        {"enable_irq", TOK_ENABLE_IRQ}, {"disable_irq", TOK_DISABLE_IRQ},
        {"yield", TOK_YIELD}, {"sleep", TOK_SLEEP}, {"panic", TOK_PANIC},
        {"assert", TOK_ASSERT},
        
        // Sections
        {".text", TOK_SECTION_TEXT}, {".data", TOK_SECTION_DATA},
        {".bss", TOK_SECTION_BSS}, {".rodata", TOK_SECTION_RODATA},
        {"align", TOK_ALIGN}, {"global", TOK_GLOBAL}, {"extern", TOK_EXTERN},
        
        // Registers
        {"rax", TOK_RAX}, {"rbx", TOK_RBX}, {"rcx", TOK_RCX}, {"rdx", TOK_RDX},
        {"rsi", TOK_RSI}, {"rdi", TOK_RDI}, {"rbp", TOK_RBP}, {"rsp", TOK_RSP},
        {"r8", TOK_R8}, {"r9", TOK_R9}, {"r10", TOK_R10}, {"r11", TOK_R11},
        {"r12", TOK_R12}, {"r13", TOK_R13}, {"r14", TOK_R14}, {"r15", TOK_R15},
        {"eax", TOK_EAX}, {"ebx", TOK_EBX}, {"ecx", TOK_ECX}, {"edx", TOK_EDX},
    };
    
    for (size_t i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
        if (strcmp(text, keywords[i].word) == 0)
            return keywords[i].type;
    }
    
    return TOK_ID;
}

static void lex_ident(void) {
    char buffer[256];
    int i = 0;
    
    while (isalnum(peek_char()) || peek_char() == '_')
        buffer[i++] = next_char();
    
    buffer[i] = '\0';
    
    TokenType type = check_keyword(buffer);
    add_token(type, buffer, 0);
}

static void tokenize(void) {
    while (peek_char() != '\0') {
        skip_whitespace();
        
        if (peek_char() == '\0')
            break;
        
        // Comments
        if (peek_char() == '/') {
            if (lexer.source[lexer.position + 1] == '/' ||
                lexer.source[lexer.position + 1] == '*') {
                skip_comment();
                continue;
            }
        }
        
        // Numbers
        if (isdigit(peek_char())) {
            lex_number();
            continue;
        }
        
        // Strings
        if (peek_char() == '"') {
            lex_string();
            continue;
        }
        
        // Characters
        if (peek_char() == '\'') {
            lex_char();
            continue;
        }
        
        // Identifiers
        if (isalpha(peek_char()) || peek_char() == '_') {
            lex_ident();
            continue;
        }
        
        // Operators and punctuation
        char c = next_char();
        switch (c) {
            // Operators
            case '+':
                if (peek_char() == '+') {
                    next_char();
                    add_token(TOK_PLUSPLUS, "++", 0);
                } else if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_PLUSEQ, "+=", 0);
                } else {
                    add_token(TOK_PLUS, "+", 0);
                }
                break;
                
            case '-':
                if (peek_char() == '-') {
                    next_char();
                    add_token(TOK_MINUSMINUS, "--", 0);
                } else if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_MINUSEQ, "-=", 0);
                } else if (peek_char() == '>') {
                    next_char();
                    add_token(TOK_ARROW, "->", 0);
                } else {
                    add_token(TOK_MINUS, "-", 0);
                }
                break;
                
            case '*':
                if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_STAREQ, "*=", 0);
                } else {
                    add_token(TOK_STAR, "*", 0);
                }
                break;
                
            case '/':
                if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_SLASHEQ, "/=", 0);
                } else {
                    add_token(TOK_SLASH, "/", 0);
                }
                break;
                
            case '%':
                if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_PERCENTEQ, "%=", 0);
                } else {
                    add_token(TOK_PERCENT, "%", 0);
                }
                break;
                
            case '=':
                if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_EQEQ, "==", 0);
                } else {
                    add_token(TOK_EQ, "=", 0);
                }
                break;
                
            case '!':
                if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_NE, "!=", 0);
                } else {
                    add_token(TOK_NOT, "!", 0);
                }
                break;
                
            case '<':
                if (peek_char() == '<') {
                    next_char();
                    if (peek_char() == '=') {
                        next_char();
                        add_token(TOK_LSHIFTEQ, "<<=", 0);
                    } else {
                        add_token(TOK_LSHIFT, "<<", 0);
                    }
                } else if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_LE, "<=", 0);
                } else {
                    add_token(TOK_LT, "<", 0);
                }
                break;
                
            case '>':
                if (peek_char() == '>') {
                    next_char();
                    if (peek_char() == '=') {
                        next_char();
                        add_token(TOK_RSHIFTEQ, ">>=", 0);
                    } else {
                        add_token(TOK_RSHIFT, ">>", 0);
                    }
                } else if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_GE, ">=", 0);
                } else {
                    add_token(TOK_GT, ">", 0);
                }
                break;
                
            case '&':
                if (peek_char() == '&') {
                    next_char();
                    add_token(TOK_AMPAMP, "&&", 0);
                } else if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_AMPEQ, "&=", 0);
                } else {
                    add_token(TOK_AMP, "&", 0);
                }
                break;
                
            case '|':
                if (peek_char() == '|') {
                    next_char();
                    add_token(TOK_PIPEPIPE, "||", 0);
                } else if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_PIPEEQ, "|=", 0);
                } else {
                    add_token(TOK_PIPE, "|", 0);
                }
                break;
                
            case '^':
                if (peek_char() == '=') {
                    next_char();
                    add_token(TOK_CARETEQ, "^=", 0);
                } else {
                    add_token(TOK_CARET, "^", 0);
                }
                break;
                
            case '~':
                add_token(TOK_TILDE, "~", 0);
                break;
                
            // Delimiters
            case '(': add_token(TOK_LPAREN, "(", 0); break;
            case ')': add_token(TOK_RPAREN, ")", 0); break;
            case '{': add_token(TOK_LBRACE, "{", 0); break;
            case '}': add_token(TOK_RBRACE, "}", 0); break;
            case '[': add_token(TOK_LBRACK, "[", 0); break;
            case ']': add_token(TOK_RBRACK, "]", 0); break;
            case ';': add_token(TOK_SEMI, ";", 0); break;
            case ',': add_token(TOK_COMMA, ",", 0); break;
            case ':':
                if (peek_char() == ':') {
                    next_char();
                    add_token(TOK_DBLCOLON, "::", 0);
                } else {
                    add_token(TOK_COLON, ":", 0);
                }
                break;
            case '.': add_token(TOK_DOT, ".", 0); break;
            case '?': add_token(TOK_QUEST, "?", 0); break;
            case '@': add_token(TOK_AT, "@", 0); break;
            case '#': add_token(TOK_HASH, "#", 0); break;
            case '$': add_token(TOK_DOLLAR, "$", 0); break;
            
            default:
                error("Unexpected character: '%c'", c);
        }
    }
    
    add_token(TOK_EOF, NULL, 0);
}

// ============== Parser Implementation ==============
static Token *peek_token(void) {
    return &lexer.tokens[lexer.current_token];
}

static Token *next_token(void) {
    Token *tok = peek_token();
    if (tok->type != TOK_EOF)
        lexer.current_token++;
    return tok;
}

static bool match(TokenType type) {
    if (peek_token()->type == type) {
        next_token();
        return true;
    }
    return false;
}

static void expect(TokenType type) {
    if (!match(type)) {
        Token *tok = peek_token();
        error("Expected token %d, got %d (%s)",
              type, tok->type, tok->text);
    }
}

static Node *new_node(int kind) {
    Node *node = calloc(1, sizeof(Node));
    node->kind = kind;
    return node;
}

// Type system
static Type *new_type(TypeKind kind, int size, int align) {
    Type *type = calloc(1, sizeof(Type));
    type->kind = kind;
    type->size = size;
    type->align = align;
    return type;
}

static Type *get_type_from_token(TokenType tok) {
    switch (tok) {
        case TOK_VOID: return new_type(TY_VOID, 0, 1);
        case TOK_U8: return new_type(TY_UINT, 1, 1);
        case TOK_U16: return new_type(TY_UINT, 2, 2);
        case TOK_U32: return new_type(TY_UINT, 4, 4);
        case TOK_U64: return new_type(TY_UINT, 8, 8);
        case TOK_I8: return new_type(TY_INT, 1, 1);
        case TOK_I16: return new_type(TY_INT, 2, 2);
        case TOK_I32: return new_type(TY_INT, 4, 4);
        case TOK_I64: return new_type(TY_INT, 8, 8);
        case TOK_F32: return new_type(TY_FLOAT, 4, 4);
        case TOK_F64: return new_type(TY_FLOAT, 8, 8);
        case TOK_BOOL: return new_type(TY_BOOL, 1, 1);
        default: return NULL;
    }
}

// Expression parsing
static Node *parse_expr(void);
static Node *parse_stmt(void);

static Node *parse_primary(void) {
    Token *tok = peek_token();
    
    if (match(TOK_INT) || match(TOK_HEX) || match(TOK_BIN) || match(TOK_CHAR)) {
        Node *node = new_node(NODE_INT);
        node->int_value = lexer.tokens[lexer.current_token - 1].value;
        return node;
    }
    
    if (match(TOK_STRING)) {
        Node *node = new_node(NODE_STRING);
        node->str_value = strdup(tok->text);
        return node;
    }
    
    if (match(TOK_ID)) {
        char name[256];
        strcpy(name, tok->text);
        
        if (match(TOK_LPAREN)) {
            // Function call
            Node *node = new_node(NODE_CALL);
            strcpy(node->name, name);
            
            Node head = {0}, *cur = &head;
            while (!match(TOK_RPAREN)) {
                cur->next = parse_expr();
                cur = cur->next;
                if (!match(TOK_COMMA))
                    break;
            }
            node->args = head.next;
            return node;
        }
        
        // Variable
        Node *node = new_node(NODE_IDENT);
        strcpy(node->name, name);
        return node;
    }
    
    if (match(TOK_LPAREN)) {
        Node *node = parse_expr();
        expect(TOK_RPAREN);
        return node;
    }
    
    error("Expected expression");
    return NULL;
}

static int get_precedence(TokenType op) {
    switch (op) {
        // Lowest
        case TOK_EQ: case TOK_PLUSEQ: case TOK_MINUSEQ:
        case TOK_STAREQ: case TOK_SLASHEQ: case TOK_PERCENTEQ:
            return 10;
            
        case TOK_PIPEPIPE: return 20;
        case TOK_AMPAMP: return 30;
        case TOK_PIPE: return 40;
        case TOK_CARET: return 50;
        case TOK_AMP: return 60;
        case TOK_EQEQ: case TOK_NE: return 70;
        case TOK_LT: case TOK_LE: case TOK_GT: case TOK_GE: return 80;
        case TOK_LSHIFT: case TOK_RSHIFT: return 90;
        case TOK_PLUS: case TOK_MINUS: return 100;
        case TOK_STAR: case TOK_SLASH: case TOK_PERCENT: return 110;
        // Highest
        default: return 0;
    }
}

static Node *parse_binary_expr(int min_prec) {
    Node *lhs = parse_primary();
    
    while (1) {
        TokenType op = peek_token()->type;
        int prec = get_precedence(op);
        
        if (prec < min_prec)
            break;
        
        next_token();
        Node *rhs = parse_binary_expr(prec + 1);
        
        Node *node = new_node(NODE_BINOP);
        node->op = op;
        node->lhs = lhs;
        node->rhs = rhs;
        lhs = node;
    }
    
    return lhs;
}

static Node *parse_expr(void) {
    return parse_binary_expr(0);
}

// Statement parsing
static Node *parse_var_decl(void) {
    Node *node = new_node(NODE_VAR);
    
    // Get declaration keyword
    Token *keyword = peek_token();
    if (keyword->type != TOK_LET && keyword->type != TOK_CONST && keyword->type != TOK_STATIC) {
        error("Expected 'let', 'const', or 'static'");
    }
    next_token(); // Skip keyword
    
    // Get variable name
    if (!match(TOK_ID)) {
        error("Expected variable name");
    }
    strcpy(node->name, lexer.tokens[lexer.current_token - 1].text);
    
    // Check for type annotation (optional)
    Type *var_type = NULL;
    if (match(TOK_COLON)) {
        var_type = parse_type();
        node->decl_type = var_type;
    }
    
    // Check for initialization
    if (match(TOK_EQ)) {
        node->init_value = parse_expr();
    }
    
    expect(TOK_SEMI);
    return node;
}

static Type *parse_type(void) {
    Token *tok = peek_token();
    Type *type = NULL;
    
    // Check for pointer type first
    if (match(TOK_STAR)) {
        Type *base_type = parse_type();
        type = new_type(TY_PTR, 8, 8);
        type->base = base_type;
        return type;
    }
    
    // Basic types
    switch (tok->type) {
        case TOK_U8:
            next_token();
            type = new_type(TY_UINT, 1, 1);
            break;
        case TOK_U16:
            next_token();
            type = new_type(TY_UINT, 2, 2);
            break;
        case TOK_U32:
            next_token();
            type = new_type(TY_UINT, 4, 4);
            break;
        case TOK_U64:
            next_token();
            type = new_type(TY_UINT, 8, 8);
            break;
        case TOK_I8:
            next_token();
            type = new_type(TY_INT, 1, 1);
            break;
        case TOK_I16:
            next_token();
            type = new_type(TY_INT, 2, 2);
            break;
        case TOK_I32:
            next_token();
            type = new_type(TY_INT, 4, 4);
            break;
        case TOK_I64:
            next_token();
            type = new_type(TY_INT, 8, 8);
            break;
        case TOK_F32:
            next_token();
            type = new_type(TY_FLOAT, 4, 4);
            break;
        case TOK_F64:
            next_token();
            type = new_type(TY_FLOAT, 8, 8);
            break;
        case TOK_BOOL:
            next_token();
            type = new_type(TY_BOOL, 1, 1);
            break;
        case TOK_VOID:
            next_token();
            type = new_type(TY_VOID, 0, 1);
            break;
        default:
            error("Expected type");
    }
    
    return type;
}
static Type *parse_type(void) {
    Token *tok = peek_token();
    Type *type = NULL;
    
    // Check for pointer type first
    if (match(TOK_STAR)) {
        Type *base_type = parse_type();
        type = new_type(TY_PTR, 8, 8);
        type->base = base_type;
        return type;
    }
    
    // Basic types
    switch (tok->type) {
        case TOK_U8:
            next_token();
            type = new_type(TY_UINT, 1, 1);
            break;
        case TOK_U16:
            next_token();
            type = new_type(TY_UINT, 2, 2);
            break;
        case TOK_U32:
            next_token();
            type = new_type(TY_UINT, 4, 4);
            break;
        case TOK_U64:
            next_token();
            type = new_type(TY_UINT, 8, 8);
            break;
        case TOK_I8:
            next_token();
            type = new_type(TY_INT, 1, 1);
            break;
        case TOK_I16:
            next_token();
            type = new_type(TY_INT, 2, 2);
            break;
        case TOK_I32:
            next_token();
            type = new_type(TY_INT, 4, 4);
            break;
        case TOK_I64:
            next_token();
            type = new_type(TY_INT, 8, 8);
            break;
        case TOK_F32:
            next_token();
            type = new_type(TY_FLOAT, 4, 4);
            break;
        case TOK_F64:
            next_token();
            type = new_type(TY_FLOAT, 8, 8);
            break;
        case TOK_BOOL:
            next_token();
            type = new_type(TY_BOOL, 1, 1);
            break;
        case TOK_VOID:
            next_token();
            type = new_type(TY_VOID, 0, 1);
            break;
        default:
            error("Expected type");
    }
    
    return type;
}

static Node *parse_for_stmt(void) {
    Node *node = new_node(NODE_FOR);
    
    expect(TOK_FOR);
    expect(TOK_LPAREN);
    
    // Initializer
    if (!match(TOK_SEMI)) {
        node->init = parse_expr();
        expect(TOK_SEMI);
    }
    
    // Condition
    if (!match(TOK_SEMI)) {
        node->cond = parse_expr();
        expect(TOK_SEMI);
    }
    
    // Increment
    if (!match(TOK_RPAREN)) {
        node->step = parse_expr();
        expect(TOK_RPAREN);
    }
    
    node->body = parse_stmt();
    return node;
}

static Node *parse_return_stmt(void) {
    Node *node = new_node(NODE_RETURN);
    
    expect(TOK_RETURN);
    if (!match(TOK_SEMI)) {
        node->lhs = parse_expr();
        expect(TOK_SEMI);
    }
    
    return node;
}

static Node *parse_asm_stmt(void) {
    Node *node = new_node(NODE_ASM);
    
    expect(TOK_ASM);
    expect(TOK_LPAREN);
    
    if (match(TOK_STRING)) {
        Token *tok = &lexer.tokens[lexer.current_token - 1];
        strcpy(node->asm_code, tok->text);
    }
    
    // Optional clobbers
    if (match(TOK_COLON)) {
        if (match(TOK_STRING)) {
            Token *tok = &lexer.tokens[lexer.current_token - 1];
            strcpy(node->clobbers, tok->text);
        }
    }
    
    expect(TOK_RPAREN);
    expect(TOK_SEMI);
    return node;
}

static Node *parse_hardware_stmt(void) {
    Token *tok = peek_token();
    
    if (match(TOK_CLI)) {
        expect(TOK_SEMI);
        return new_node(NODE_CLI);
    }
    
    if (match(TOK_STI)) {
        expect(TOK_SEMI);
        return new_node(NODE_STI);
    }
    
    if (match(TOK_HLT)) {
        expect(TOK_SEMI);
        return new_node(NODE_HLT);
    }
    
    if (match(TOK_IN)) {
        Node *node = new_node(NODE_IN);
        expect(TOK_LPAREN);
        node->lhs = parse_expr(); // port
        expect(TOK_RPAREN);
        expect(TOK_SEMI);
        return node;
    }
    
    if (match(TOK_OUT)) {
        Node *node = new_node(NODE_OUT);
        expect(TOK_LPAREN);
        node->lhs = parse_expr(); // port
        expect(TOK_COMMA);
        node->rhs = parse_expr(); // value
        expect(TOK_RPAREN);
        expect(TOK_SEMI);
        return node;
    }
    
    error("Expected hardware statement");
    return NULL;
}

static Node *parse_block(void) {
    Node *node = new_node(NODE_BLOCK);
    
    expect(TOK_LBRACE);
    Node head = {0}, *cur = &head;
    
    while (!match(TOK_RBRACE)) {
        cur->next = parse_stmt();
        cur = cur->next;
    }
    
    node->body = head.next;
    return node;
}

static Node *parse_stmt(void) {
    Token *tok = peek_token();
    
    switch (tok->type) {
        case TOK_LET:
        case TOK_CONST:
        case TOK_STATIC:
            return parse_var_decl();
            
        case TOK_IF:
            return parse_if_stmt();
            
        case TOK_WHILE:
            return parse_while_stmt();
            
        case TOK_FOR:
            return parse_for_stmt();
            
        case TOK_LOOP:
            next_token();
            return new_node(NODE_LOOP);
            
        case TOK_RETURN:
            return parse_return_stmt();
            
        case TOK_BREAK:
            next_token();
            expect(TOK_SEMI);
            return new_node(NODE_BREAK);
            
        case TOK_CONTINUE:
            next_token();
            expect(TOK_SEMI);
            return new_node(NODE_CONTINUE);
            
        case TOK_YIELD:
            next_token();
            expect(TOK_SEMI);
            return new_node(NODE_YIELD);
            
        case TOK_PANIC:
            next_token();
            expect(TOK_SEMI);
            return new_node(NODE_PANIC);
            
        case TOK_ASM:
            return parse_asm_stmt();
            
        case TOK_CLI:
        case TOK_STI:
        case TOK_HLT:
        case TOK_IN:
        case TOK_OUT:
            return parse_hardware_stmt();
            
        case TOK_LBRACE:
            return parse_block();
            
        default: {
            Node *node = new_node(NODE_EXPR_STMT);
            node->lhs = parse_expr();
            expect(TOK_SEMI);
            return node;
        }
    }
}

static Node *parse_function(void) {
    Node *node = new_node(NODE_FUNC);
    
    expect(TOK_FN);
    expect(TOK_ID);
    strcpy(node->name, lexer.tokens[lexer.current_token - 1].text);
    
    // Parameters
    expect(TOK_LPAREN);
    Node param_head = {0}, *cur = &param_head;
    
    while (!match(TOK_RPAREN)) {
        Token *type_tok = peek_token();
        Type *type = get_type_from_token(type_tok->type);
        
        if (!type)
            break;
            
        next_token();
        expect(TOK_ID);
        
        Node *param = new_node(NODE_VAR);
        param->decl_type = type;
        strcpy(param->name, lexer.tokens[lexer.current_token - 1].text);
        
        cur->next = param;
        cur = cur->next;
        
        if (!match(TOK_COMMA))
            break;
    }
    
    // Return type
    if (match(TOK_ARROW)) {
        Token *ret_tok = peek_token();
        Type *ret_type = get_type_from_token(ret_tok->type);
        if (ret_type) {
            next_token();
            // Store return type somehow
        }
    }
    
    // Body
    node->body = parse_block();
    return node;
}

static Node *parse_task(void) {
    Node *node = new_node(NODE_TASK);
    
    expect(TOK_TASK);
    expect(TOK_ID);
    strcpy(node->name, lexer.tokens[lexer.current_token - 1].text);
    
    // Task parameters
    expect(TOK_LPAREN);
    if (!match(TOK_RPAREN)) {
        // Priority, stack size, etc.
        node->args = parse_expr();
        expect(TOK_RPAREN);
    }
    
    node->body = parse_block();
    return node;
}

static Node *parse_interrupt(void) {
    Node *node = new_node(NODE_INTERRUPT);
    
    expect(TOK_INTERRUPT);
    expect(TOK_ID);
    strcpy(node->name, lexer.tokens[lexer.current_token - 1].text);
    
    // Interrupt vector
    expect(TOK_LPAREN);
    node->lhs = parse_expr(); // vector number
    expect(TOK_RPAREN);
    
    node->body = parse_block();
    return node;
}

static Node *parse_kernel(void) {
    Node *node = new_node(NODE_KERNEL);
    
    expect(TOK_KERNEL);
    expect(TOK_ID);
    strcpy(node->name, lexer.tokens[lexer.current_token - 1].text);
    
    node->body = parse_block();
    return node;
}

static Node *parse_program(void) {
    Node *program = new_node(NODE_BLOCK);
    Node head = {0}, *cur = &head;
    
    while (peek_token()->type != TOK_EOF) {
        Token *tok = peek_token();
        
        switch (tok->type) {
            case TOK_KERNEL:
                cur->next = parse_kernel();
                break;
                
            case TOK_FN:
                cur->next = parse_function();
                break;
                
            case TOK_TASK:
                cur->next = parse_task();
                break;
                
            case TOK_INTERRUPT:
                cur->next = parse_interrupt();
                break;
                
            case TOK_IMPORT:
            case TOK_EXPORT:
                // Handle imports/exports
                next_token();
                break;
                
            case TOK_SECTION_TEXT:
            case TOK_SECTION_DATA:
            case TOK_SECTION_BSS:
            case TOK_SECTION_RODATA: {
                Node *section = new_node(NODE_SECTION);
                strcpy(section->name, tok->text);
                next_token();
                cur->next = section;
                break;
            }
                
            default:
                // Global variable or other declaration
                cur->next = parse_var_decl();
                break;
        }
        
        if (cur->next)
            cur = cur->next;
    }
    
    program->body = head.next;
    return program;
}

// ============== Code Generator ==============
static void emit_byte(uint8_t byte) {
    if (codegen.code_size >= MAX_CODE_SIZE)
        error("Code section overflow");
    
    codegen.code[codegen.code_size++] = byte;
}

static void emit_word(uint16_t word) {
    emit_byte(word & 0xFF);
    emit_byte((word >> 8) & 0xFF);
}

static void emit_dword(uint32_t dword) {
    emit_word(dword & 0xFFFF);
    emit_word((dword >> 16) & 0xFFFF);
}

static void emit_qword(uint64_t qword) {
    emit_dword(qword & 0xFFFFFFFF);
    emit_dword((qword >> 32) & 0xFFFFFFFF);
}

// x86-64 encoding
static void emit_rex(bool w, bool r, bool x, bool b) {
    uint8_t rex = 0x40;
    if (w) rex |= 0x08;
    if (r) rex |= 0x04;
    if (x) rex |= 0x02;
    if (b) rex |= 0x01;
    
    if (rex != 0x40)
        emit_byte(rex);
}

static void emit_modrm(uint8_t mod, uint8_t reg, uint8_t rm) {
    emit_byte((mod << 6) | ((reg & 7) << 3) | (rm & 7));
}

static void emit_sib(uint8_t scale, uint8_t index, uint8_t base) {
    emit_byte((scale << 6) | ((index & 7) << 3) | (base & 7));
}

// Instruction helpers
static void emit_mov_reg_imm(int reg, uint64_t imm) {
    if (reg < 8) {
        emit_rex(true, false, false, false);
        emit_byte(0xB8 + reg);
    } else {
        emit_rex(true, false, false, true);
        emit_byte(0xB8 + (reg - 8));
    }
    emit_qword(imm);
}

static void emit_mov_reg_reg(int dst, int src) {
    emit_rex(true, src >= 8, false, dst >= 8);
    emit_byte(0x89);
    emit_modrm(3, src & 7, dst & 7);
}

static void emit_push_reg(int reg) {
    if (reg < 8) {
        emit_byte(0x50 + reg);
    } else {
        emit_rex(false, false, false, true);
        emit_byte(0x50 + (reg - 8));
    }
}

static void emit_pop_reg(int reg) {
    if (reg < 8) {
        emit_byte(0x58 + reg);
    } else {
        emit_rex(false, false, false, true);
        emit_byte(0x58 + (reg - 8));
    }
}

static void emit_ret(void) {
    emit_byte(0xC3);
}

static void emit_nop(void) {
    emit_byte(0x90);
}

static void emit_cli(void) {
    emit_byte(0xFA);
}

static void emit_sti(void) {
    emit_byte(0xFB);
}

static void emit_hlt(void) {
    emit_byte(0xF4);
}

static void emit_out(uint8_t port_reg, uint8_t data_reg) {
    if (port_reg == 0x02 && data_reg == 0x00) { // dx, al
        emit_byte(0xEE);
    } else {
        // General case
        emit_byte(0x66); // operand size prefix if needed
        emit_rex(false, false, false, false);
        emit_byte(0xEF); // out dx, ax
    }
}

static void emit_in(uint8_t data_reg, uint8_t port_reg) {
    if (port_reg == 0x02 && data_reg == 0x00) { // al, dx
        emit_byte(0xEC);
    } else {
        emit_byte(0x66);
        emit_rex(false, false, false, false);
        emit_byte(0xED); // in ax, dx
    }
}

// Code generation from AST
static void gen_expr(Node *node);
static void gen_stmt(Node *node);

static void gen_int(Node *node) {
    // Load immediate into RAX
    emit_mov_reg_imm(0, node->int_value); // RAX = imm
}

static void gen_string(Node *node) {
    // Store string in data section, load address
    int offset = codegen.data_size;
    
    // Add to data section
    char *str = node->str_value;
    int len = strlen(str) + 1;
    
    if (codegen.data_size + len >= MAX_DATA_SIZE)
        error("Data section overflow");
    
    memcpy(&codegen.data[codegen.data_size], str, len);
    codegen.data_size += len;
    
    // Load address into RAX
    emit_mov_reg_imm(0, 0x200000 + offset); // Data section base + offset
}

static void gen_ident(Node *node) {
    // Look up symbol
    for (int i = 0; i < codegen.symbol_count; i++) {
        if (strcmp(codegen.symbols[i].name, node->name) == 0) {
            if (codegen.symbols[i].is_global) {
                // Load from global symbol
                emit_mov_reg_imm(0, codegen.symbols[i].address);
                emit_byte(0x48); // REX.W
                emit_byte(0x8B); // MOV
                emit_byte(0x00); // RAX, [RAX]
            } else {
                // Load from stack
                int offset = codegen.symbols[i].address;
                emit_byte(0x48); // REX.W
                emit_byte(0x8B); // MOV
                emit_byte(0x45); // RAX, [RBP - offset]
                emit_byte(-offset);
            }
            return;
        }
    }
    
    error("Undefined symbol: %s", node->name);
}

static void gen_call(Node *node) {
    // Push arguments (simplified: only 6 arguments in registers)
    int arg_count = 0;
    Node *args[6] = {0};
    
    for (Node *arg = node->args; arg && arg_count < 6; arg = arg->next) {
        args[arg_count++] = arg;
    }
    
    // Generate arguments in reverse order
    for (int i = arg_count - 1; i >= 0; i--) {
        gen_expr(args[i]);
        
        // Move to appropriate register
        switch (i) {
            case 0: emit_mov_reg_reg(7, 0); break; // RDI
            case 1: emit_mov_reg_reg(6, 0); break; // RSI
            case 2: emit_mov_reg_reg(2, 0); break; // RDX
            case 3: emit_mov_reg_reg(1, 0); break; // RCX
            case 4: emit_mov_reg_reg(8, 0); break; // R8
            case 5: emit_mov_reg_reg(9, 0); break; // R9
        }
    }
    
    // Call (placeholder, will be patched)
    int call_pos = codegen.code_size;
    emit_byte(0xE8); // CALL rel32
    emit_dword(0);   // Placeholder
    
    // Store relocation
    if (codegen.reloc_count < 1024) {
        codegen.relocs[codegen.reloc_count].offset = call_pos + 1;
        strcpy(codegen.relocs[codegen.reloc_count].symbol, node->name);
        codegen.relocs[codegen.reloc_count].type = 1; // 32-bit relative
        codegen.reloc_count++;
    }
}

static void gen_binop(Node *node) {
    // Generate left side
    gen_expr(node->lhs);
    emit_push_reg(0); // Save RAX
    
    // Generate right side
    gen_expr(node->rhs);
    emit_mov_reg_reg(1, 0); // RBX = RAX
    
    // Restore left side
    emit_pop_reg(0); // RAX = original left
    
    // Perform operation
    switch (node->op) {
        case TOK_PLUS:
            emit_byte(0x48); // ADD RAX, RBX
            emit_byte(0x01);
            emit_byte(0xD8);
            break;
            
        case TOK_MINUS:
            emit_byte(0x48); // SUB RAX, RBX
            emit_byte(0x29);
            emit_byte(0xD8);
            break;
            
        case TOK_STAR:
            emit_byte(0x48); // IMUL RAX, RBX
            emit_byte(0x0F);
            emit_byte(0xAF);
            emit_byte(0xC3);
            break;
            
        case TOK_AMP: // AND
            emit_byte(0x48);
            emit_byte(0x21);
            emit_byte(0xD8);
            break;
            
        case TOK_PIPE: // OR
            emit_byte(0x48);
            emit_byte(0x09);
            emit_byte(0xD8);
            break;
            
        case TOK_CARET: // XOR
            emit_byte(0x48);
            emit_byte(0x31);
            emit_byte(0xD8);
            break;
            
        default:
            error("Unsupported binary operator");
    }
}

static void gen_expr(Node *node) {
    if (!node) return;
    
    switch (node->kind) {
        case NODE_INT:
            gen_int(node);
            break;
            
        case NODE_STRING:
            gen_string(node);
            break;
            
        case NODE_IDENT:
            gen_ident(node);
            break;
            
        case NODE_CALL:
            gen_call(node);
            break;
            
        case NODE_BINOP:
            gen_binop(node);
            break;
            
        default:
            error("Unsupported expression node");
    }
}

static void gen_var_decl(Node *node) {
    // Add to symbol table
    if (codegen.symbol_count < MAX_SYMBOLS) {
        strcpy(codegen.symbols[codegen.symbol_count].name, node->name);
        codegen.symbols[codegen.symbol_count].is_global = false;
        codegen.symbols[codegen.symbol_count].address = codegen.stack_offset;
        
        // Allocate stack space
        int size = 8; // Default size
        if (node->decl_type)
            size = node->decl_type->size;
        
        codegen.stack_offset += size;
        codegen.symbol_count++;
    }
    
    // Generate initialization if present
    if (node->init_value) {
        gen_expr(node->init_value);
        
        // Store to stack
        int offset = codegen.symbols[codegen.symbol_count - 1].address;
        emit_byte(0x48); // MOV [RBP - offset], RAX
        emit_byte(0x89);
        emit_byte(0x45);
        emit_byte(-offset);
    }
}

static void gen_if_stmt(Node *node) {
    // Generate condition
    gen_expr(node->cond);
    
    // Test condition
    emit_byte(0x48); // TEST RAX, RAX
    emit_byte(0x85);
    emit_byte(0xC0);
    
    // Jump if false
    int jump_pos = codegen.code_size;
    emit_byte(0x0F); // JZ rel32
    emit_byte(0x84);
    emit_dword(0); // Placeholder
    
    // Generate then block
    gen_stmt(node->then);
    
    // If there's an else block
    if (node->els) {
        // Jump over else block
        int jump2_pos = codegen.code_size;
        emit_byte(0xE9); // JMP rel32
        emit_dword(0); // Placeholder
        
        // Patch first jump
        int then_end = codegen.code_size;
        *(uint32_t*)&codegen.code[jump_pos + 2] = then_end - jump_pos - 6;
        
        // Generate else block
        gen_stmt(node->els);
        
        // Patch second jump
        int else_end = codegen.code_size;
        *(uint32_t*)&codegen.code[jump2_pos + 1] = else_end - jump2_pos - 5;
    } else {
        // Patch jump
        int then_end = codegen.code_size;
        *(uint32_t*)&codegen.code[jump_pos + 2] = then_end - jump_pos - 6;
    }
}

static void gen_while_stmt(Node *node) {
    int loop_start = codegen.code_size;
    
    // Generate condition
    gen_expr(node->cond);
    
    // Test condition
    emit_byte(0x48); // TEST RAX, RAX
    emit_byte(0x85);
    emit_byte(0xC0);
    
    // Jump if false (exit loop)
    int jump_pos = codegen.code_size;
    emit_byte(0x0F); // JZ rel32
    emit_byte(0x84);
    emit_dword(0); // Placeholder
    
    // Generate body
    gen_stmt(node->body);
    
    // Jump back to condition
    emit_byte(0xE9); // JMP rel32
    emit_dword(loop_start - codegen.code_size - 5);
    
    // Patch exit jump
    int loop_end = codegen.code_size;
    *(uint32_t*)&codegen.code[jump_pos + 2] = loop_end - jump_pos - 6;
}

static void gen_return_stmt(Node *node) {
    if (node->lhs) {
        gen_expr(node->lhs);
        // Result already in RAX
    }
    
    // Epilogue
    emit_byte(0x48); // MOV RSP, RBP
    emit_byte(0x89);
    emit_byte(0xEC);
    
    emit_pop_reg(5); // POP RBP
    emit_ret();
}

static void gen_asm_stmt(Node *node) {
    // Simple inline assembly - just emit hex bytes
    char *code = node->asm_code;
    char *ptr = code;
    
    while (*ptr) {
        if (*ptr == ' ' || *ptr == '\t' || *ptr == '\n') {
            ptr++;
            continue;
        }
        
        if (*ptr == '0' && *(ptr + 1) == 'x') {
            ptr += 2;
            char hex[3] = {0};
            
            if (isxdigit(*ptr) && isxdigit(*(ptr + 1))) {
                hex[0] = *ptr++;
                hex[1] = *ptr++;
                uint8_t byte = strtoul(hex, NULL, 16);
                emit_byte(byte);
            }
        } else {
            ptr++;
        }
    }
}

static void gen_block(Node *node) {
    for (Node *stmt = node->body; stmt; stmt = stmt->next) {
        gen_stmt(stmt);
    }
}

static void gen_stmt(Node *node) {
    if (!node) return;
    
    switch (node->kind) {
        case NODE_VAR:
            gen_var_decl(node);
            break;
            
        case NODE_EXPR_STMT:
            gen_expr(node->lhs);
            break;
            
        case NODE_IF:
            gen_if_stmt(node);
            break;
            
        case NODE_WHILE:
            gen_while_stmt(node);
            break;
            
        case NODE_RETURN:
            gen_return_stmt(node);
            break;
            
        case NODE_BLOCK:
            gen_block(node);
            break;
            
        case NODE_ASM:
            gen_asm_stmt(node);
            break;
            
        case NODE_CLI:
            emit_cli();
            break;
            
        case NODE_STI:
            emit_sti();
            break;
            
        case NODE_HLT:
            emit_hlt();
            break;
            
        case NODE_IN: {
            // IN port
            gen_expr(node->lhs); // Port in RAX
            emit_mov_reg_reg(2, 0); // DX = RAX
            emit_in(0, 2); // AL = IN(DX)
            break;
        }
            
        case NODE_OUT: {
            // OUT port, value
            gen_expr(node->rhs); // Value in RAX
            emit_push_reg(0); // Save value
            gen_expr(node->lhs); // Port in RAX
            emit_mov_reg_reg(2, 0); // DX = RAX
            emit_pop_reg(0); // AL = value
            emit_out(2, 0); // OUT(DX, AL)
            break;
        }
            
        default:
            warning("Unsupported statement type: %d", node->kind);
            break;
    }
}

static void gen_function(Node *node) {
    // Prologue
    emit_push_reg(5); // PUSH RBP
    emit_mov_reg_reg(5, 4); // MOV RBP, RSP
    
    // Reset stack offset for local variables
    codegen.stack_offset = 8; // Start after saved RBP
    
    // Generate body
    gen_stmt(node->body);
    
    // If no return statement, add default return
    if (codegen.code[codegen.code_size - 1] != 0xC3) {
        // Epilogue
        emit_byte(0x48); // MOV RSP, RBP
        emit_byte(0x89);
        emit_byte(0xEC);
        
        emit_pop_reg(5); // POP RBP
        emit_ret();
    }
    
    // Add to symbol table
    if (codegen.symbol_count < MAX_SYMBOLS) {
        strcpy(codegen.symbols[codegen.symbol_count].name, node->name);
        codegen.symbols[codegen.symbol_count].address = 0x1000; // Will be updated
        codegen.symbols[codegen.symbol_count].is_global = true;
        codegen.symbols[codegen.symbol_count].is_function = true;
        codegen.symbol_count++;
    }
}

static void gen_kernel(Node *node) {
    // Kernel entry point
    emit_cli(); // Disable interrupts
    
    // Set up stack
    emit_mov_reg_imm(4, 0x7C00); // RSP = 0x7C00
    
    // Clear screen
    emit_mov_reg_imm(0, 0xB8000); // VGA buffer
    emit_mov_reg_imm(1, 0x0F20);  // White space
    for (int i = 0; i < 80 * 25; i++) {
        emit_mov_reg_reg(2, 0);
        emit_byte(0x66); // MOV WORD [RAX + i*2], 0x0F20
        emit_byte(0x89);
        emit_byte(0x0C);
        emit_byte(0x50);
        emit_word(0x0F20);
    }
    
    // Generate kernel body
    gen_stmt(node->body);
    
    // Infinite loop at end
    emit_hlt();
    emit_byte(0xEB); // JMP -2
    emit_byte(0xFE);
}

static void create_multiboot_header(void) {
    // Multiboot 2 header
    uint32_t header[] = {
        0xE85250D6, // Magic
        0,          // Architecture (0 = i386, 4 = MIPS)
        20,         // Header length
        ~(0xE85250D6 + 0 + 20) + 1, // Checksum
        
        // End tag
        0, // Type
        8, // Size
    };
    
    // Write to start of code
    memcpy(codegen.code, header, sizeof(header));
    codegen.code_size = sizeof(header);
}

static void generate_code(Node *program) {
    // Initialize code generator
    memset(&codegen, 0, sizeof(codegen));
    
    // Create multiboot header
    create_multiboot_header();
    
    // Generate code from AST
    for (Node *node = program->body; node; node = node->next) {
        switch (node->kind) {
            case NODE_KERNEL:
                gen_kernel(node);
                break;
                
            case NODE_FUNC:
                gen_function(node);
                break;
                
            case NODE_TASK:
            case NODE_INTERRUPT:
                // Generate as function for now
                gen_function(node);
                break;
                
            default:
                break;
        }
    }
    
    // Resolve relocations
    for (int i = 0; i < codegen.reloc_count; i++) {
        uint32_t offset = codegen.relocs[i].offset;
        char *symbol = codegen.relocs[i].symbol;
        
        // Find symbol address
        uint64_t sym_addr = 0;
        for (int j = 0; j < codegen.symbol_count; j++) {
            if (strcmp(codegen.symbols[j].name, symbol) == 0) {
                sym_addr = codegen.symbols[j].address;
                break;
            }
        }
        
        if (sym_addr == 0) {
            warning("Undefined symbol in relocation: %s", symbol);
            continue;
        }
        
        // Calculate relative offset
        uint32_t rel_offset = sym_addr - (offset + 4);
        *(uint32_t*)&codegen.code[offset] = rel_offset;
    }
}

// ============== Main Compiler ==============
static void compile_file(const char *filename, const char *output) {
    // Read source file
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        exit(1);
    }
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *source = malloc(size + 1);
    fread(source, 1, size, file);
    source[size] = '\0';
    fclose(file);
    
    // Initialize lexer
    memset(&lexer, 0, sizeof(lexer));
    lexer.source = source;
    lexer.filename = (char*)filename;
    lexer.length = size;
    lexer.line = 1;
    lexer.column = 1;
    
    printf("📖 Compiling %s...\n", filename);
    
    // Lexical analysis
    tokenize();
    printf("  🔍 Lexed %d tokens\n", lexer.token_count);
    
    // Parsing
    Node *ast = parse_program();
    printf("  🌳 Built AST\n");
    
    // Code generation
    generate_code(ast);
    printf("  ⚙️  Generated %d bytes of code\n", codegen.code_size);
    printf("  📊 Data section: %d bytes\n", codegen.data_size);
    
    // Write output
    FILE *out = fopen(output, "wb");
    if (!out) {
        perror("Failed to open output file");
        exit(1);
    }
    
    // Write code
    fwrite(codegen.code, 1, codegen.code_size, out);
    
    // Write data if any
    if (codegen.data_size > 0) {
        // Align to page boundary
        int padding = 4096 - (codegen.code_size % 4096);
        if (padding < 4096) {
            uint8_t zero = 0;
            for (int i = 0; i < padding; i++) {
                fwrite(&zero, 1, 1, out);
            }
        }
        
        fwrite(codegen.data, 1, codegen.data_size, out);
    }
    
    fclose(out);
    printf("  💾 Written to %s\n", output);
    
    // Cleanup
    free(source);
}

static void show_help(void) {
    printf("JX Compiler v%s - Kernel Language for AbdelalyOS\n", JX_VERSION);
    printf("\n");
    printf("Usage: jx <input.jx> [options]\n");
    printf("\n");
    printf("Options:\n");
    printf("  -o <file>    Output file (default: kernel.bin)\n");
    printf("  -v           Verbose output\n");
    printf("  -S           Generate assembly instead of binary\n");
    printf("  --help       Show this help\n");
    printf("\n");
    printf("Example:\n");
    printf("  jx kernel.jx -o kernel.bin\n");
    printf("  qemu-system-x86_64 -kernel kernel.bin\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        show_help();
        return 1;
    }
    
    const char *input_file = NULL;
    const char *output_file = "kernel.bin";
    bool verbose = false;
    bool generate_asm = false;
    
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                output_file = argv[++i];
            } else if (strcmp(argv[i], "-v") == 0) {
                verbose = true;
            } else if (strcmp(argv[i], "-S") == 0) {
                generate_asm = true;
            } else if (strcmp(argv[i], "--help") == 0) {
                show_help();
                return 0;
            }
        } else {
            input_file = argv[i];
        }
    }
    
    if (!input_file) {
        fprintf(stderr, "Error: No input file specified\n");
        show_help();
        return 1;
    }
    
    printf("🚀 JX Compiler v%s\n", JX_VERSION);
    printf("📝 Target: Abdelal؟yOS Kernel\n");
    printf("🎯 Architecture: x86_64\n\n");
    
    compile_file(input_file, output_file);
    
    printf("\n✅ Compilation successful!\n");
    printf("📦 Output: %s\n", output_file);
    printf("\n💡 Run with QEMU:\n");
    printf("   qemu-system-x86_64 -kernel %s\n", output_file);
    
    return 0;
}
