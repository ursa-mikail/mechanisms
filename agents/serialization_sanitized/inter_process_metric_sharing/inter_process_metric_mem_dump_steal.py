import multiprocessing
import time
import random
from ctypes import c_char, cast, POINTER, addressof
from multiprocessing import shared_memory

OFFSET = 100

def metric_writer(shm_name):
    shm = shared_memory.SharedMemory(name=shm_name)
    buf_type = c_char * shm.size
    buf = buf_type.from_buffer(shm.buf)

    addr = addressof(buf)
    print(f"[Writer] Shared memory address: {hex(addr)}")

    val = random.randint(100, 200)
    val_bytes = val.to_bytes(4, 'little')
    for i in range(4):
        buf[i] = val_bytes[i]

    print(f"[Writer] Wrote value {val} ( hex: {hex(val)}) at address {hex(addr)}")    

    offset = OFFSET

    val = random.randint(100, 200)
    val_bytes = val.to_bytes(4, 'little')

    for i in range(4):
        buf[i + offset] = val_bytes[i]    

    print(f"[Writer] Wrote value {val} ( hex: {hex(val)} ) at address {hex(addr + offset)}")
    time.sleep(5)
    del buf  # Important: release exported pointers
    shm.close()

def metric_stealer(shm_name):
    time.sleep(1)  # wait for writer
    shm = shared_memory.SharedMemory(name=shm_name)

    buf_type = c_char * shm.size
    buf = buf_type.from_buffer(shm.buf)

    addr = addressof(buf)
    print(f"[Stealer] Shared memory address: {hex(addr)}")

    offset = OFFSET + 1
    #dump_range = range(shm.size)
    dump_range = range(offset)
    # join bytes slices to single bytes object
    bytes_around = b''.join(buf[i] for i in dump_range)

    print(f"[Stealer] Memory dump ±20 bytes around address {hex(addr)}:")
    print(bytes_around.hex())

    int_val = int.from_bytes(bytes_around[:4], 'little')
    print(f"[Stealer] Integer value read: {int_val} ( hex: {hex(int_val)} ) ")

    int_val = int.from_bytes(bytes_around[-1:], 'little')
    print(f"[Stealer] Integer value read: {int_val} ( hex: {hex(int_val)} ) ")

    del buf  # release exported pointers
    shm.close()

if __name__ == "__main__":
    shm = shared_memory.SharedMemory(create=True, size=64)

    # clip OFFSET <= shm.size
    print(f"OFFSET: {OFFSET}")
    context = shared_memory.SharedMemory(shm.name)

    if OFFSET > context.size:
        print(f"OFFSET of {OFFSET} clipped to {context.size}")
        OFFSET = context.size - 4   # need -4 as minimal
        print(f"OFFSET clipped to {OFFSET}")


    try:
        writer = multiprocessing.Process(target=metric_writer, args=(shm.name,))
        stealer = multiprocessing.Process(target=metric_stealer, args=(shm.name,))

        writer.start()
        stealer.start()

        writer.join()
        stealer.join()
    finally:
        shm.close()
        shm.unlink()

"""
OFFSET: 100
OFFSET of 100 clipped to 64
OFFSET clipped to 60
[Writer] Shared memory address: 0x7ba47e3c3000
[Writer] Wrote value 128 ( hex: 0x80) at address 0x7ba47e3c3000
[Writer] Wrote value 105 ( hex: 0x69 ) at address 0x7ba47e3c303c
[Stealer] Shared memory address: 0x7ba47e3c3000
[Stealer] Memory dump ±20 bytes around address 0x7ba47e3c3000:
80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000069
[Stealer] Integer value read: 128 ( hex: 0x80 ) 
[Stealer] Integer value read: 105 ( hex: 0x69 ) 
"""

import multiprocessing
import time
import os
import random


def metric_writer(shared_dict):
    """Simulate metric gathering and store in shared dict."""
    pid = os.getpid()
    addr = hex(id(shared_dict))
    shared_dict['metric'] = {
        'pid': pid,
        'address': addr,
        'value': random.randint(100, 200)
    }
    print(f"[Writer] PID {pid} stored metric at address {addr}")
    time.sleep(5)  # Keep process alive

def metric_stealer(shared_dict):
    """Simulate another process reading (stealing) the metric."""
    time.sleep(1)  # Wait for writer to populate
    stolen = shared_dict.get('metric', None)
    if stolen:
        print(f"[Stealer] Stole metric from PID {stolen['pid']}")
        print(f"[Stealer] Address: {stolen['address']} | Value: {stolen['value']}")
    else:
        print("[Stealer] No metric found")

if __name__ == "__main__":
    with multiprocessing.Manager() as manager:
        shared_dict = manager.dict()

        writer = multiprocessing.Process(target=metric_writer, args=(shared_dict,))
        stealer = multiprocessing.Process(target=metric_stealer, args=(shared_dict,))

        writer.start()
        stealer.start()

        writer.join()
        stealer.join()

"""
[Writer] PID 54288 stored metric at address 0x7ba45871e950
[Stealer] Stole metric from PID 54288
[Stealer] Address: 0x7ba45871e950 | Value: 140


"""        