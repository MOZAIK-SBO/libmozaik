import struct

# Read numbers from the file
with open("sample.txt", "r") as file:
    numbers = file.readline().split()

# Multiply each number by 2^8 and convert to integer
integers = [int(round(float(num) * 2**8)) for num in numbers]

print(integers)

# Convert integers to 64-bit little-endian representation and concatenate
little_endian = b"".join([struct.pack("<q", num) for num in integers])

print(little_endian.hex())

# Append the string to the file
with open("sample_bytes.txt", "wb") as file:
    file.write(b"\n" + little_endian)
