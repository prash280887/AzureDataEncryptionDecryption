namespace Common.Encryption
{
    using System;
    using System.Text;

    /// <summary>
    /// The StringEncryptor
    /// </summary>
    /// <seealso cref="IEncryptor{String}" />
    public class StringEncryptor : IEncryptor<string>
    {
        /// <summary>
        /// The cipher
        /// </summary>
        private readonly ICipher cipher;

        /// <summary>
        /// Gets or sets the key version.
        /// </summary>
        /// <value>
        /// The key version.
        /// </value>
        public string KeyVersion { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="StringEncryptor"/> class.
        /// </summary>
        /// <param name="cipher">The cipher.</param>
        public StringEncryptor(ICipher cipher)
        {
            this.cipher = cipher;
            this.KeyVersion = cipher.KeyVersion;
        }

        /// <summary>
        /// Decrypts the specified object.
        /// </summary>
        /// <param name="obj">The object.</param>
        /// <returns>
        /// The decrypted object
        /// </returns>
        public string Decrypt(string obj)
        {
            if (string.IsNullOrEmpty(obj))
            {
                return obj;
            }

            var encryptedBytes = GetBase64Bytes(obj);
            var decreyptedBytes = this.cipher.Decrypt(encryptedBytes);          
           return GetUTF8String(decreyptedBytes);

           // return this.cipher.DecryptToText(encryptedBytes);
        }

        /// <summary>
        /// Encrypts the specified object.
        /// </summary>
        /// <param name="obj">The object.</param>
        /// <returns>
        /// The encrypted object
        /// </returns>
        public string Encrypt(string obj)
        {
            if (string.IsNullOrEmpty(obj))
            {
                return obj;
            }

            var dataAsBytes = GetUTF8Bytes(obj);
            var encryptedBytes = this.cipher.Encrypt(dataAsBytes);
            return GetBase64String(encryptedBytes);
        }

        /// <summary>
        /// Gets the string.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <returns>The base64 string</returns>
        private static string GetBase64String(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Gets the UTF8 string.
        /// </summary>
        /// <param name="bytes">The bytes.</param>
        /// <returns>The UTF8 string</returns>
        private static string GetUTF8String(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Gets the bytes.
        /// </summary>
        /// <param name="str">The string.</param>
        /// <returns>The UTF8 bytes</returns>
        private static byte[] GetBase64Bytes(string str)
        {
            return Convert.FromBase64String(str);
        }

        /// <summary>
        /// Gets the UTF8 bytes.
        /// </summary>
        /// <param name="str">The string.</param>
        /// <returns>The UTF8 bytes</returns>
        private static byte[] GetUTF8Bytes(string str)
        {
            return Encoding.UTF8.GetBytes(str);
        }
    }
}
