import ast
import operator as op
from cryptography.fernet import Fernet
import binascii

# Allowed operators for secure evaluation
allowed_ops = {
    ast.BitAnd: op.and_,
    ast.BitOr: op.or_,
    ast.BitXor: op.xor,
    ast.Invert: op.invert,
    ast.Or: op.or_,
    ast.And: op.and_,
    ast.Not: op.not_,
    ast.Expr: lambda x: x,
    ast.USub: lambda x: -x,
    ast.UnaryOp: lambda x: x,
}

def eval_expr(expr, variables):
    def _eval(node):
        if isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.Name):
            return variables[node.id]
        elif isinstance(node, ast.BinOp):
            return allowed_ops[type(node.op)](_eval(node.left), _eval(node.right))
        elif isinstance(node, ast.UnaryOp):
            return allowed_ops[type(node.op)](_eval(node.operand))
        else:
            raise TypeError(f"Unsupported type: {type(node)}")
    return _eval(ast.parse(expr, mode='eval').body)

# Example: more complex logic
operator_expr = "not (a & b) | c"

# Inputs
inputs = {'a': 0, 'b': 0, 'c': 0}

# Encrypt outputs for all combinations
data = []
for a in range(0,2):
    for b in range(0,2):
        for c in range(0,2):
            val = eval_expr(operator_expr, {'a': a, 'b': b, 'c': c}) & 0x01
            data.append(str(val))

# Now encrypt these using 3 input keys (a, b, c) and simulate multi-layer encryption

# Generate keys
keys = {
    'a_0': Fernet.generate_key(),
    'a_1': Fernet.generate_key(),
    'b_0': Fernet.generate_key(),
    'b_1': Fernet.generate_key(),
    'c_0': Fernet.generate_key(),
    'c_1': Fernet.generate_key(),
}

# Encrypt using layers
cipher_matrix = []
for idx, val in enumerate(data):
    a = (idx >> 2) & 1
    b = (idx >> 1) & 1
    c = (idx >> 0) & 1
    encrypted = Fernet(keys[f'c_{c}']).encrypt(
                  Fernet(keys[f'b_{b}']).encrypt(
                    Fernet(keys[f'a_{a}']).encrypt(val.encode())))
    cipher_matrix.append(encrypted)

# Decrypt
a_val, b_val, c_val = 0, 0, 0
try:
    decrypted = Fernet(keys[f'a_{a_val}']).decrypt(
                    Fernet(keys[f'b_{b_val}']).decrypt(
                        Fernet(keys[f'c_{c_val}']).decrypt(cipher_matrix[0])))
    print("Decrypted value:", decrypted)
except Exception as e:
    print("Failed to decrypt:", e)

"""
### More Complex Logic
Parentheses
Combinations like not (a & b) or c
Multi-variable logic (with mapping from a, b, c… to real values)

out: Decrypted value: b'1'
"""