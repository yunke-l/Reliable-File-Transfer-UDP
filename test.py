def divide_chunks_in_batches_with_seq(content: bytes, chunk_size: int, batch_size: int, start_chunk: int):
    # Initialize an empty list to accumulate chunks and the starting sequence number
    batch = []
    seq = start_chunk * chunk_size  # Calculate the starting sequence number (based on the chunk number)

    for i in range(start_chunk * chunk_size, len(content), chunk_size):
        chunk = content[i:i + chunk_size]
        batch.append((seq, chunk))  # Store both the sequence number and chunk

        # Once we reach the desired batch size, yield the batch and reset it
        if len(batch) == batch_size:
            yield batch
            batch = []  # Reset for next batch

        seq += chunk_size  # Increase seq by chunk_size after each chunk

    # If there are any remaining chunks that didn't form a full batch
    if batch:
        yield batch

data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # Example data
chunk_size = 5
batch_size = 3
start_chunk = 1  # Start from the second chunk (index 1)

# Generate chunks in batches with sequence numbers
batches = divide_chunks_in_batches_with_seq(data, chunk_size, batch_size, start_chunk)

for batch in batches:
    for seq, chunk in batch:
        print(f"Seq {seq}: {chunk}")