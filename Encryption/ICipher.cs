namespace Common.Encryption
{
    /// <summary>
    /// The ICipher
    /// </summary>
    public interface ICipher
    {
        /// <summary>
        /// Gets or sets the key version.
        /// </summary>
        /// <value>
        /// The key version.
        /// </value>
        string KeyVersion { get; set; }

        /// <summary>
        /// Encrypts the specified data to encrypt.
        /// </summary>
        /// <param name="dataToEncrypt">The data to encrypt.</param>
        /// <returns>The encrypted bytes</returns>
        byte[] Encrypt(byte[] dataToEncrypt);

        /// <summary>
        /// Decrypts the specified data to decrypt.
        /// </summary>
        /// <param name="dataToDecrypt">The data to decrypt.</param>
        /// <returns>The decrypted bytes</returns>
        byte[] Decrypt(byte[] dataToDecrypt);


        string DecryptToText(byte[] dataToDecrypt);
    }
}
