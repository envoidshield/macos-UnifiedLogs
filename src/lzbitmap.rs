// Copyright 2026 Envoid, Inc.
// Licensed under the Apache License, Version 2.0.
//
// Decoder structure derived from Ernesto A. Fernández's MIT-licensed
// libzbitmap implementation: https://github.com/eafer/libzbitmap

const MAGIC: &[u8; 4] = b"ZBM\x09";
const CHUNK_HEADER_SIZE: usize = 6;
const COMPRESSED_CHUNK_HEADER_SIZE: usize = 15;
const MAX_DECOMPRESSED_CHUNK_SIZE: usize = 0x8000;
const BITMAP_COUNT: usize = 12;
const BITMAP_BYTE_COUNT: usize = 17;

#[derive(Clone, Copy, Default)]
struct Bitmap {
    bits: u8,
    period_bytes: u8,
}

struct NibbleCursor {
    offset: usize,
    high: bool,
}

impl NibbleCursor {
    fn read(&mut self, data: &[u8]) -> Result<u8, &'static str> {
        let byte = *data.get(self.offset).ok_or("truncated bitmap metadata")?;
        if self.high {
            self.high = false;
            self.offset += 1;
            Ok(byte >> 4)
        } else {
            self.high = true;
            Ok(byte & 0x0f)
        }
    }

    fn rewind(&mut self) -> Result<(), &'static str> {
        if self.high {
            self.high = false;
        } else {
            self.offset = self
                .offset
                .checked_sub(1)
                .ok_or("invalid bitmap metadata rewind")?;
            self.high = true;
        }
        Ok(())
    }
}

fn read_u24(data: &[u8], offset: usize) -> Result<usize, &'static str> {
    let bytes = data
        .get(offset..offset + 3)
        .ok_or("truncated LZBITMAP integer")?;
    Ok(usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16))
}

fn read_bitmaps(chunk: &[u8]) -> Result<[Bitmap; BITMAP_COUNT], &'static str> {
    if chunk.len() < BITMAP_BYTE_COUNT {
        return Err("truncated LZBITMAP bitmap table");
    }

    let table = &chunk[chunk.len() - BITMAP_BYTE_COUNT..];
    let mut bit_offset = 0;
    let mut bitmaps = [Bitmap::default(); BITMAP_COUNT];
    for bitmap in &mut bitmaps {
        let mut bits = 0;
        for bit in 0..8 {
            let value = (table[bit_offset / 8] >> (bit_offset % 8)) & 1;
            bits |= value << bit;
            bit_offset += 1;
        }

        let mut period_bytes = 0;
        for bit in 0..2 {
            let value = (table[bit_offset / 8] >> (bit_offset % 8)) & 1;
            period_bytes |= value << bit;
            bit_offset += 1;
        }
        if period_bytes > 2 {
            return Err("invalid LZBITMAP period width");
        }
        *bitmap = Bitmap { bits, period_bytes };
    }
    Ok(bitmaps)
}

struct ChunkDecoder<'a> {
    chunk: &'a [u8],
    output: &'a mut Vec<u8>,
    expected_size: usize,
    written: usize,
    period: usize,
    data_offset: usize,
    meta_1_offset: usize,
    meta_2_offset: usize,
    meta_3: NibbleCursor,
    bitmaps: [Bitmap; BITMAP_COUNT],
}

impl ChunkDecoder<'_> {
    fn read_repetition_count(&mut self) -> Result<usize, &'static str> {
        if self.expected_size - self.written <= 8 {
            return Ok(1);
        }

        let mut nibble = self.meta_3.read(self.chunk)?;
        if nibble != 0x0f {
            self.meta_3.rewind()?;
            return Ok(1);
        }

        let mut total = 4usize;
        while nibble == 0x0f {
            nibble = self.meta_3.read(self.chunk)?;
            total = total
                .checked_add(usize::from(nibble))
                .ok_or("LZBITMAP repetition count overflow")?;
        }
        Ok(total)
    }

    fn apply_bitmap_number(&mut self, bitmap_number: u8) -> Result<(), &'static str> {
        let bitmap = match bitmap_number {
            0..=2 => {
                let bits = *self
                    .chunk
                    .get(self.meta_2_offset)
                    .ok_or("truncated LZBITMAP bitmap metadata")?;
                self.meta_2_offset += 1;
                Bitmap {
                    bits,
                    period_bytes: bitmap_number,
                }
            }
            3..=14 => self.bitmaps[usize::from(bitmap_number - 3)],
            _ => return Err("invalid LZBITMAP bitmap number"),
        };

        if bitmap.period_bytes != 0 {
            self.period = 0;
            for byte_index in 0..bitmap.period_bytes {
                let byte = *self
                    .chunk
                    .get(self.meta_1_offset)
                    .ok_or("truncated LZBITMAP period metadata")?;
                self.meta_1_offset += 1;
                self.period |= usize::from(byte) << (usize::from(byte_index) * 8);
            }
        }
        if self.period == 0 {
            return Err("invalid zero LZBITMAP period");
        }

        for bit in 0..8 {
            if self.written == self.expected_size {
                break;
            }
            let value = if bitmap.bits & (1 << bit) != 0 {
                let value = *self
                    .chunk
                    .get(self.data_offset)
                    .ok_or("truncated LZBITMAP literal data")?;
                self.data_offset += 1;
                value
            } else {
                let source = self
                    .output
                    .len()
                    .checked_sub(self.period)
                    .ok_or("invalid LZBITMAP back-reference")?;
                self.output[source]
            };
            self.output.push(value);
            self.written += 1;
        }
        Ok(())
    }

    fn decode(mut self) -> Result<(), &'static str> {
        while self.written < self.expected_size {
            let bitmap_number = self.meta_3.read(self.chunk)?;
            let repetitions = self.read_repetition_count()?;
            for _ in 0..repetitions {
                self.apply_bitmap_number(bitmap_number)?;
            }
        }
        Ok(())
    }
}

fn decompress_chunk(
    chunk: &[u8],
    output: &mut Vec<u8>,
    expected_size: usize,
) -> Result<(), &'static str> {
    if chunk.len() == expected_size + CHUNK_HEADER_SIZE {
        output.extend_from_slice(
            chunk
                .get(CHUNK_HEADER_SIZE..)
                .ok_or("truncated uncompressed LZBITMAP chunk")?,
        );
        return Ok(());
    }
    if chunk.len() < COMPRESSED_CHUNK_HEADER_SIZE {
        return Err("truncated compressed LZBITMAP chunk header");
    }

    let meta_1_offset = read_u24(chunk, 6)?;
    let meta_2_offset = read_u24(chunk, 9)?;
    let meta_3_offset = read_u24(chunk, 12)?;
    if meta_1_offset >= chunk.len() || meta_2_offset >= chunk.len() || meta_3_offset >= chunk.len()
    {
        return Err("invalid LZBITMAP metadata offset");
    }

    ChunkDecoder {
        chunk,
        output,
        expected_size,
        written: 0,
        period: 8,
        data_offset: COMPRESSED_CHUNK_HEADER_SIZE,
        meta_1_offset,
        meta_2_offset,
        meta_3: NibbleCursor {
            offset: meta_3_offset,
            high: false,
        },
        bitmaps: read_bitmaps(chunk)?,
    }
    .decode()
}

pub(crate) fn decompress(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if !data.starts_with(MAGIC) {
        return Err("invalid LZBITMAP magic");
    }

    let mut offset = MAGIC.len();
    let mut output = Vec::new();
    loop {
        let chunk_length = read_u24(data, offset)?;
        let decompressed_length = read_u24(data, offset + 3)?;
        if chunk_length < CHUNK_HEADER_SIZE {
            return Err("invalid LZBITMAP chunk length");
        }
        if decompressed_length > MAX_DECOMPRESSED_CHUNK_SIZE {
            return Err("LZBITMAP chunk exceeds maximum decompressed size");
        }

        let chunk_end = offset
            .checked_add(chunk_length)
            .ok_or("LZBITMAP chunk length overflow")?;
        let chunk = data
            .get(offset..chunk_end)
            .ok_or("truncated LZBITMAP chunk")?;
        if decompressed_length == 0 {
            return Ok(output);
        }

        output
            .try_reserve(decompressed_length)
            .map_err(|_| "LZBITMAP output allocation failed")?;
        decompress_chunk(chunk, &mut output, decompressed_length)?;
        offset = chunk_end;
    }
}
