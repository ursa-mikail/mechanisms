import json
import pickle
import io
import sys
from typing import Any, Dict, List

# ==========================================
# SECURE ALTERNATIVES TO PICKLE
# ==========================================

def safe_serialize_with_json(data: Dict[str, Any]) -> str:
    """Safe serialization using JSON - no code execution possible."""
    try:
        return json.dumps(data, indent=2)
    except (TypeError, ValueError) as e:
        print(f"JSON serialization failed: {e}")
        return None

def safe_deserialize_with_json(json_data: str) -> Dict[str, Any]:
    """Safe deserialization using JSON."""
    try:
        return json.loads(json_data)
    except (json.JSONDecodeError, TypeError) as e:
        print(f"JSON deserialization failed: {e}")
        return None

# ==========================================
# PICKLE SECURITY MEASURES
# ==========================================

class RestrictedUnpickler(pickle.Unpickler):
    """Custom unpickler that restricts dangerous operations."""
    
    # Whitelist of safe modules/classes
    SAFE_MODULES = {
        'builtins': {'dict', 'list', 'tuple', 'set', 'frozenset', 'int', 'float', 'str', 'bool'},
        'collections': {'defaultdict', 'OrderedDict', 'Counter'},
        'datetime': {'datetime', 'date', 'time'},
    }
    
    def find_class(self, module, name):
        """Override to restrict which classes can be unpickled."""
        if module in self.SAFE_MODULES:
            if name in self.SAFE_MODULES[module]:
                return getattr(__import__(module), name)
        
        # Log the blocked attempt
        print(f"SECURITY: Blocked attempt to load {module}.{name}")
        raise pickle.UnpicklingError(f"Class {module}.{name} is not allowed")

def safe_pickle_loads(data: bytes) -> Any:
    """Safely unpickle data with restrictions."""
    try:
        with io.BytesIO(data) as f:
            unpickler = RestrictedUnpickler(f)
            return unpickler.load()
    except (pickle.UnpicklingError, EOFError, AttributeError) as e:
        print(f"Safe unpickling failed: {e}")
        return None

# ==========================================
# VALIDATION AND SANITIZATION
# ==========================================

def validate_data_structure(data: Any, max_depth: int = 10, current_depth: int = 0) -> bool:
    """Validate data structure to prevent deeply nested attacks."""
    if current_depth > max_depth:
        print("SECURITY: Data structure too deeply nested")
        return False
    
    if isinstance(data, dict):
        if len(data) > 1000:  # Prevent large dict attacks
            print("SECURITY: Dictionary too large")
            return False
        return all(validate_data_structure(v, max_depth, current_depth + 1) for v in data.values())
    
    elif isinstance(data, (list, tuple)):
        if len(data) > 1000:  # Prevent large list attacks
            print("SECURITY: List/tuple too large")
            return False
        return all(validate_data_structure(item, max_depth, current_depth + 1) for item in data)
    
    elif isinstance(data, (str, int, float, bool, type(None))):
        return True
    
    else:
        print(f"SECURITY: Unexpected data type: {type(data)}")
        return False

# ==========================================
# SECURE DATA SHARING EXAMPLE
# ==========================================

class SecureDataExchange:
    """Demonstrates secure ways to share data between processes."""
    
    def __init__(self):
        self.allowed_keys = {'metrics', 'status', 'config', 'timestamp'}
    
    def serialize_safely(self, data: Dict[str, Any]) -> str:
        """Serialize data using safe JSON method."""
        # Validate data first
        if not self.validate_payload(data):
            raise ValueError("Data validation failed")
        
        return safe_serialize_with_json(data)
    
    def deserialize_safely(self, serialized_data: str) -> Dict[str, Any]:
        """Deserialize data with validation."""
        data = safe_deserialize_with_json(serialized_data)
        
        if data and self.validate_payload(data):
            return data
        else:
            raise ValueError("Invalid or unsafe data received")
    
    def validate_payload(self, data: Dict[str, Any]) -> bool:
        """Validate payload structure and content."""
        if not isinstance(data, dict):
            print("SECURITY: Payload must be a dictionary")
            return False
        
        # Check for allowed keys only
        if not all(key in self.allowed_keys for key in data.keys()):
            print("SECURITY: Payload contains disallowed keys")
            return False
        
        # Validate data structure
        return validate_data_structure(data)

# ==========================================
# DEMONSTRATION
# ==========================================

def demonstrate_secure_practices():
    """Show secure serialization practices."""
    print("=== SECURE DATA SERIALIZATION DEMO ===\n")
    
    # Example data
    safe_data = {
        'metrics': {'cpu': 45.2, 'memory': 78.1},
        'status': 'healthy',
        'timestamp': '2025-06-12T10:30:00Z'
    }
    
    print("1. Safe JSON Serialization:")
    print("-" * 30)
    
    # Safe serialization
    exchange = SecureDataExchange()
    try:
        serialized = exchange.serialize_safely(safe_data)
        print("✓ Data serialized safely:")
        print(serialized)
        
        # Safe deserialization
        deserialized = exchange.deserialize_safely(serialized)
        print("\n✓ Data deserialized safely:")
        print(deserialized)
        
    except Exception as e:
        print(f"✗ Error: {e}")
    
    print("\n2. Pickle Security Demonstration:")
    print("-" * 35)
    
    # Show safe pickle usage with restrictions
    safe_pickle_data = pickle.dumps({'safe': 'data', 'number': 42})
    
    print("✓ Safe pickle data created")
    result = safe_pickle_loads(safe_pickle_data)
    print(f"✓ Safe unpickling result: {result}")
    
    print("\n3. Security Best Practices:")
    print("-" * 30)
    print("✓ Use JSON for data serialization when possible")
    print("✓ Validate all incoming data")
    print("✓ Restrict pickle to trusted sources only")
    print("✓ Use custom unpicklers with whitelists")
    print("✓ Implement data structure validation")
    print("✓ Log security events for monitoring")

if __name__ == "__main__":
    demonstrate_secure_practices()

"""
=== SECURE DATA SERIALIZATION DEMO ===

1. Safe JSON Serialization:
------------------------------
✓ Data serialized safely:
{
  "metrics": {
    "cpu": 45.2,
    "memory": 78.1
  },
  "status": "healthy",
  "timestamp": "2025-06-12T10:30:00Z"
}

✓ Data deserialized safely:
{'metrics': {'cpu': 45.2, 'memory': 78.1}, 'status': 'healthy', 'timestamp': '2025-06-12T10:30:00Z'}

2. Pickle Security Demonstration:
-----------------------------------
✓ Safe pickle data created
✓ Safe unpickling result: {'safe': 'data', 'number': 42}

3. Security Best Practices:
------------------------------
✓ Use JSON for data serialization when possible
✓ Validate all incoming data
✓ Restrict pickle to trusted sources only
✓ Use custom unpicklers with whitelists
✓ Implement data structure validation
✓ Log security events for monitoring
"""    