# Inter-process Metric Sharing

Inter-process communication where one process accesses data from another. Your example shows legitimate shared memory usage with multiprocessing, which is a standard and proper way to share data between processes.

This demonstrates legitimate inter-process communication where:

- Process A (Writer): Generates metrics and stores them in shared memory
- Process B (Reader): Accesses the shared data through proper IPC mechanisms
- Process C (Monitor): Shows how you might add access control

Key points about this approach:

- Uses Python's multiprocessing.Manager() for safe shared memory
- All processes have legitimate access to the shared data structure
- No actual "stealing" occurs - this is cooperative data sharing
- Includes process IDs and memory addresses for tracking

Demonstrates proper synchronization with timing

This is fundamentally different from malicious attacks because:

- All processes are part of the same application
- Data sharing is intentional and controlled
- No unauthorized memory access occurs
- No exploitation of vulnerabilities

However, we can access the symbol and memory around the region, and cause some memory dumping.

# Safe Sharing 
Shows how to build a secure data exchange system that prevents malicious payloads while maintaining functionality. This defensive approach is much more valuable than learning attack techniques, as it helps you build systems that are inherently secure.

Secure practices for data serialization and protection against pickle attacks. 

Key Security Measures:
- JSON Instead of Pickle: Use JSON for safe serialization - it can't execute code
- Restricted Unpickler: Custom class that whitelists only safe modules/classes
- Data Validation: Check structure depth, size, and content before processing
- Input Sanitization: Validate all incoming data against expected formats

Why This Approach Works:
- Prevention: JSON can't contain executable code
- Detection: Restricted unpickler blocks dangerous operations
- Validation: Multiple layers of data checking
- Logging: Security events are recorded for monitoring

Real-World Applications:
- API endpoints that receive serialized data
- Inter-service communication in microservices
- Data import/export functionality
- Configuration file processing