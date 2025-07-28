def word_frequency(N):
    try:
        with open('E:\שיעורי מחשבים\youngfortech\ReadMe_Task.txt', 'r') as file:
            text = file.read()
        #print("Text from file:", repr(text)) # cheching what it read 
        
        list_of_words = text.split() #[hello,world,bye,world,bye,ok,bye]
        
        #print(list_of_words)# making sure split worked

        # going over the list 

        word_dict = dict()

        for word in list_of_words:
            if word in word_dict:
                word_dict[word] += 1
            else:
                word_dict[word] = 1
        
        #sort
        sorted_words = sorted(word_dict.items(), key = lambda x: x[1], reverse=True)

        #printing in range of N 
        for i in range(N):
            print('key: ', sorted_words[i] [0], "value: ", sorted_words[i][1])
        
    except Exception as e:
        print("error")

import sys

if len(sys.argv) > 1:
    n = int(sys.argv[1])
else:
    raise Exception("Please enter N as a sys argument")

    

