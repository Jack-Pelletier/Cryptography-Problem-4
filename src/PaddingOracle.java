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
 import javax.crypto.Cipher;
 import java.security.NoSuchAlgorithmException;
 import javax.crypto.NoSuchPaddingException;
 import javax.crypto.spec.SecretKeySpec;
 import javax.crypto.SecretKey;
 import java.security.InvalidKeyException;
 import javax.crypto.IllegalBlockSizeException;
 import javax.crypto.BadPaddingException;
 import java.util.Base64;
 import java.security.InvalidAlgorithmParameterException;
 import javax.crypto.spec.IvParameterSpec;
 import java.io.File;
 import java.io.FileNotFoundException;
 import java.util.Scanner;
 import java.util.ArrayList;

 /**
  * This is an implementation of the decryption oracle object. It behaves as a limited
  * oracle that reports true if decryption was successful and false otherwise.
  * The decryption fails if a BadPaddingException occurs.
  *
  * @author Zach Kissel
  */
public class PaddingOracle 
{
  private SecretKey key;              // Holds the secret key read from the file.

  /**
   * The constructor takes a key file  and loads the AES key into the
   * oracle.
   *
   * @param keyFile the name of the file containing a Base64 encoded key.
   */
  public PaddingOracle(String keyFile) throws FileNotFoundException
  {
    File file = new File(keyFile);
    String b64Key;

    // Check if the file exists if not, we can't read the key.
    if (!file.exists())
      throw new FileNotFoundException("Key File " + keyFile + " does not exist.");

    Scanner in = new Scanner(file);     // Bind the scanner to the file.

    // Read the Base 64 encoded key.
    b64Key = in.nextLine();
    in.close();

    // Build the SecretKey object.
    key = new SecretKeySpec(Base64.getDecoder().decode(b64Key), "AES");
  }

  /**
   * Decrypt the ciphertext with the given IV.
   *
   * @param blocks the ciphertext as a sequence of blocks. The first 
   * block holds the IV for decryption.
   *
   * @return true if the decryption is successful and false otherwise. The only 
   * way decryption will fail is if there is a padding error.
   */
  public boolean decrypt(ArrayList<Block> blocks)
  {
    // Set up an AES cipher object.
		Cipher aesCipher = null;

    try 
    {
      aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    } 
    catch (NoSuchAlgorithmException | NoSuchPaddingException e) 
    {
      System.out.println(e);
      System.out.println("Can't continue -- unexpected error.");
      System.exit(1);
    }

    // Put the cipher in decryption mode with the specified key.
		try {
      aesCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(blocks.get(0).toArray()));
    } 
    catch (InvalidKeyException | InvalidAlgorithmParameterException e)
    {
      System.out.println(e);
      System.out.println("Can't continue -- unexpected error.");
      System.exit(1);
    }

    // Perform the decryption.
    try
    {
      for (int i = 1; i < blocks.size(); i++)
        aesCipher.update(blocks.get(i).toArray());
      aesCipher.doFinal();        // Complete the encryption, ignore the result.
    }
    catch (BadPaddingException badPadding)
    {
      return false;
    } 
    catch (IllegalBlockSizeException e) 
    {
      System.out.println(e);
      System.out.println("Are you sure you provide 16 byte blocks?");
      System.exit(1);
    }
    
    return true;
  }
}
