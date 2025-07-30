counter = 0

def function_plus():
    global counter
    for i in range(100000):
        counter += 1

def function_minus():
    global counter
    for i in range(100000):
        counter -= 1

import threading

thread1 = threading.Thread(target=function_plus)
thread2 = threading.Thread(target=function_minus)

thread1.start()
thread2.start()

thread1.join()
thread2.join()

print(counter)