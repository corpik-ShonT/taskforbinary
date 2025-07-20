def decimal_to_binary(decimal, bit_width):
    binary = bin(decimal)[2:]  # Convert positive decimal to binary representation

    if len(binary) < bit_width:
        binary = binary.zfill(bit_width)  # Zero-fill the binary representation
    else:
        binary = binary[-bit_width:]  # Truncate to the specified bit width
    return binary


def apply_twos_complement(binary, bit_width):    
    inverted = ''.join('1' if bit == '0' else '0' for bit in binary)  # Invert all the bits
    inverted_decimal = int(inverted, 2) + 1
    negative_binary = decimal_to_binary(inverted_decimal, bit_width)
    return negative_binary

# Main program
decimal = int(input("Enter a decimal number: "))

binary = decimal_to_binary(decimal, 8)
negative_binary = apply_twos_complement(binary, 8)
print("Negative binary representation (two's complement):", negative_binary)
