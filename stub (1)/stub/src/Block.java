/*
 *   Copyright (C) 2019 -- 2024  Zachary A. Kissel
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * This class represents a ciphertext/message block. This object is 
 * immutable.
 */
public class Block 
{
    private byte[] data;            // The data associated with the block.

    /**
     * Constrcuts a new block of 16 bytes of zeros.
     */
    public Block()
    {
        data = new byte[16];
    }

    /**
     * Construct a new block with the given data.
     * @param data a 16 byte data block.
     * @throws IllegalArgumentException if the block is not 16 bytes in size.
     */
    public Block(byte[] data) throws IllegalArgumentException
    {
        if (data.length != 16)
            throw new IllegalArgumentException("Blocks must be 16 bytes in size.");

        this.data = data.clone();       // Let's make a deep copy.
    }

    /**
     * xors this block with the {@code other} block and returns a new 
     * block representing the result.
     * @param other the block to xor with.
     * @return a new Block that is the xor of {@code this} and {@code other}.
     */
    public Block xor(Block other)
    {
        byte[] res = new byte[this.data.length];
        for (int i = 0; i < this.data.length; i++)
            res[i] = (byte) (this.data[i] ^ other.data[i]);

        return new Block(res);
    }

    /**
     * Set byte {@code idx} of the block to {@code b}
     * @param idx the byte within the block to set.
     * @param b the value to set the byte to.
     * @return A new block with byte {@code idx} set to {@code b}.
     * @throws IndexOutOfBoundsException if {@code idx} is not between 0 
     * and 15 inclusive.
     */
    public Block setByte(int idx, byte b) throws IndexOutOfBoundsException
    {
        if (idx > 16 || idx < 0)
            throw new IndexOutOfBoundsException("index out of bounds.");

        Block rv = new Block();
        rv.data = data.clone();
        rv.data[idx] = b;
        return rv;
    }

    /**
     * Get a byte at position {@code idx} in the block.
     * 
     * @param idx the position of the byte to retrieve
     * @return the value at position {@code idx}
     * @throws IndexOutOfBoundsException if {@code idx} is not between 0
     * and 15 inclusive.
     */
    public byte getByte(int idx) throws IndexOutOfBoundsException
    {
        if (idx > 16 || idx < 0)
            throw new IndexOutOfBoundsException("index out of bounds.");
        return data[idx];
    }

    /**
     * Gets a copy of the data in the block as a 16-byte array.
     * @return a copy of the data in the block.
     */
    public byte[] toArray()
    {
        return data.clone();
    }

    /**
     * Convert the block to a string representation.
     * @return a string representation of the block.
     */
    public String toString() 
    {
        String res = "";
        for (int i = 0; i < data.length; i++)
            res += String.format("0x%02x ", data[i]);
        return res;
    }
}
