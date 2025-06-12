import multiprocessing
import time
import os
import random

def metric_writer(shared_dict):
    """Process that generates and stores metrics in shared memory."""
    pid = os.getpid()
    addr = hex(id(shared_dict))
    
    # Simulate continuous metric collection
    for i in range(3):
        metric_data = {
            'pid': pid,
            'address': addr,
            'value': random.randint(100, 200),
            'timestamp': time.time(),
            'iteration': i + 1
        }
        shared_dict['metric'] = metric_data
        print(f"[Writer] PID {pid} stored metric #{i+1} at address {addr}")
        time.sleep(2)

def metric_reader(shared_dict):
    """Process that reads metrics from shared memory."""
    reader_pid = os.getpid()
    time.sleep(1)  # Wait for writer to populate
    
    for i in range(3):
        metric = shared_dict.get('metric', None)
        if metric:
            print(f"[Reader] PID {reader_pid} read metric from writer PID {metric['pid']}")
            print(f"[Reader] Address: {metric['address']} | Value: {metric['value']} | Iteration: {metric['iteration']}")
        else:
            print(f"[Reader] No metric found at attempt {i+1}")
        time.sleep(2)

def secure_metric_monitor(shared_dict, process_name):
    """Enhanced version with proper access control simulation."""
    monitor_pid = os.getpid()
    print(f"[{process_name}] Monitor started with PID {monitor_pid}")
    
    # Simulate access verification
    authorized = True  # In real implementation, this would check permissions
    
    if not authorized:
        print(f"[{process_name}] Access denied - insufficient permissions")
        return
    
    for i in range(2):
        metric = shared_dict.get('metric', None)
        if metric:
            print(f"[{process_name}] Authorized access to metric from PID {metric['pid']}")
            print(f"[{process_name}] Value: {metric['value']} at {metric['timestamp']}")
        time.sleep(3)

if __name__ == "__main__":
    print("=== Basic Inter-Process Communication ===")
    
    with multiprocessing.Manager() as manager:
        shared_dict = manager.dict()
        
        # Create processes
        writer = multiprocessing.Process(target=metric_writer, args=(shared_dict,))
        reader = multiprocessing.Process(target=metric_reader, args=(shared_dict,))
        monitor = multiprocessing.Process(target=secure_metric_monitor, args=(shared_dict, "Monitor"))
        
        # Start all processes
        writer.start()
        reader.start()
        monitor.start()
        
        # Wait for completion
        writer.join()
        reader.join()
        monitor.join()
        
    print("\n=== Process Communication Complete ===")
    print("Note: This demonstrates legitimate shared memory usage")
    print("All processes have proper access to the shared data structure")

"""
=== Basic Inter-Process Communication ===
[Writer] PID 12356 stored metric #1 at address 0x7ba47014da10
[Monitor] Monitor started with PID 12365
[Monitor] Authorized access to metric from PID 12356
[Monitor] Value: 131 at 1749751632.5176737
[Reader] PID 12361 read metric from writer PID 12356
[Reader] Address: 0x7ba47014da10 | Value: 131 | Iteration: 1
[Writer] PID 12356 stored metric #2 at address 0x7ba47014da10
[Reader] PID 12361 read metric from writer PID 12356
[Reader] Address: 0x7ba47014da10 | Value: 155 | Iteration: 2
[Monitor] Authorized access to metric from PID 12356
[Monitor] Value: 155 at 1749751634.5688968
[Writer] PID 12356 stored metric #3 at address 0x7ba47014da10
[Reader] PID 12361 read metric from writer PID 12356
[Reader] Address: 0x7ba47014da10 | Value: 198 | Iteration: 3

=== Process Communication Complete ===
Note: This demonstrates legitimate shared memory usage
All processes have proper access to the shared data structure
"""