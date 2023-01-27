namespace Common.Encryption
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    /// <summary>
    /// The AesCipher
    /// </summary>
    /// <seealso cref="Common.Encryption.ICipher" />
    public class AesCipher : ICipher
    {
        /// <summary>
        /// The key
        /// </summary>
        private readonly byte[] key;

        /// <summary>
        /// The iv
        /// </summary>
        private readonly byte[] iv;

        /// <summary>
        /// Gets or sets the key version.
        /// </summary>
        /// <value>
        /// The key version.
        /// </value>
        public string KeyVersion { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCipher" /> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="iv">The iv.</param>
        /// <param name="keyVersion">The key version.</param>
        public AesCipher(byte[] key, byte[] iv)
        {
            this.key = key;
            this.iv = iv;
        }

        /// <summary>
        /// Decrypts the specified data.
        /// </summary>
        /// <param name="dataToDecrypt">The data to decrypt.</param>
        /// <returns>The decrypted bytes</returns>
        public byte[] Decrypt(byte[] dataToDecrypt)
        {
          //  Requires.NotNullOrEmpty(dataToDecrypt, nameof(dataToDecrypt));

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                aes.Key = this.key;
                aes.IV = this.iv;

                using (var memoryStream = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write);

                    cryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
                    cryptoStream.FlushFinalBlock();

                    var decryptBytes = memoryStream.ToArray();

                    return decryptBytes;
                }
            }
        }

        public string DecryptToText(byte[] cipherText)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (this.key == null || this.key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (this.iv == null || this.iv.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an AesCryptoServiceProvider object
            // with the specified key and IV.
            using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                aesAlg.Key = this.key;
                aesAlg.IV = this.iv;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="dataToEncrypt">The data to encrypt.</param>
        /// <returns>The encrypted bytes</returns>
        public byte[] Encrypt(byte[] dataToEncrypt)
        {
          //  Requires.NotNullOrEmpty(dataToEncrypt, nameof(dataToEncrypt));

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                aes.Key = this.key;
                aes.IV = this.iv;

                using (var memoryStream = new MemoryStream())
                {
                    var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

                    cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    cryptoStream.FlushFinalBlock();

                    return memoryStream.ToArray();
                }
            }
        }
    }
}
