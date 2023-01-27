namespace Common.Encryption
{
    /// <summary>
    /// The IEncryptor
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface IEncryptor<T>
    {
        /// <summary>
        /// Gets or sets the key version.
        /// </summary>
        /// <value>
        /// The key version.
        /// </value>
        string KeyVersion { get; set; }

        /// <summary>
        /// Encrypts the specified object.
        /// </summary>
        /// <param name="obj">The object.</param>
        /// <returns>The encrypted object</returns>
        T Encrypt(T obj);

        /// <summary>
        /// Decrypts the specified object.
        /// </summary>
        /// <param name="obj">The object.</param>
        /// <returns>The decrypted object</returns>
        T Decrypt(T obj);
    }
}
