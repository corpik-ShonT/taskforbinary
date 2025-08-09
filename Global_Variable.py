from threading import Thread
counter = 0

def function_plus():
    global counter
    for i in range(100000):
        counter += 1

def function_minus():
    global counter
    for i in range(100000):
        counter -= 1

thread1 = Thread(target=function_plus)
thread2 = Thread(target=function_minus)

thread1.start()
thread2.start()

#Wait for threads to fin
thread1.join()
thread2.join()

#Print the final value of the counter
print(f"the final counter: {counter}")