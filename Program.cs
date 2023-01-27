using System;
using System.Configuration;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;
using Common.Encryption;
using Microsoft.Identity.Client.Platforms.Features.DesktopOs.Kerberos;

namespace AzEncryptDecryptDataConsole
{
    #region README 
    /// <summary>
    /// Developed by - Prashant Akhouri
    /// Dataed - 26 Jan 2023
    /// Oranisation - Microsoft Corporation
    /// Alias - prakhour@microsoft.com , prakhour@outlook.com
    /// </summary>
    #endregion
    internal class Program
    {       
        
        //note - Program uses managedidenity DefaultAzureCredential(); ,so register azure login account in keyvault preferably with full permissions
        //and stay signed in vsts (options-> azure service authetication) with same azure account 
            

        private static StringEncryptor converter;
  
        static async Task Main(string[] args)
        {

            Console.WriteLine(" Press 1 to start connect your environment ( optionally , you can add more environment)");
            string env = Console.ReadLine();


            switch (env)
            {
                case "1":
                    //DEV
                    Console.WriteLine("Environment : [DEV]");
                    break;
            
            }

            Console.Write(Environment.NewLine + " Connecting KeyVault...");
            //Initialize EncryptorDecryptor
            var cryptographyClient = InitializeCrypto();
            Console.Write("success..Initializing Encryptor Decryptor.... please wait !");
            converter = await GetEncryptorDecryptor(cryptographyClient);
            Console.Clear();
            Console.WriteLine(Environment.NewLine + "******  Data Encryptor - Decryptor is ready ********");

            do
            {
                Console.WriteLine(Environment.NewLine + "---------------------------------------------------------------------");
                Console.WriteLine(Environment.NewLine + "Type option  - 0. Create CipherText Secret for KV 1. Encrypt Text 2. Decrypt Text (  any other character to Exit ) ");
                string input = Console.ReadLine();
                bool iscorrect = int.TryParse(input, out int ch);


                if (iscorrect)
                {
                    var result = "";
                    switch (ch)
                    {
                        case 0: Console.WriteLine(Environment.NewLine + "[Encrypted CipherText Secret Creation]"); result = GetCipherTextString(); break;
                        case 1: Console.WriteLine(Environment.NewLine + "[Encryption]"); result = RunEncryption(); break;
                        case 2: Console.WriteLine(Environment.NewLine + "[Decryption]"); result = RunDecryption(); break;

                        default: Console.WriteLine("Invalid Choice"); break;
                    }

                    Console.WriteLine(Environment.NewLine + "Output -> " + Environment.NewLine + result.ToString());
                }
                else
                {
                    Environment.Exit(0);
                }

            } while (true);
        }


        /// <summary>
        /// Encryption - Input a text to get the encrypted string
        /// </summary>
        /// <returns></returns>
        static string RunEncryption()
        {

            Console.WriteLine(Environment.NewLine + "Type DB Profile Text to Encrypt");
            string textToEncrypt = Console.ReadLine();
            var response = converter.Encrypt(textToEncrypt); 
            return response;
        }


        /// <summary>
        /// Decryption - Input the encrypted string to Decrypt
        /// </summary>
        /// <returns></returns>
        static string RunDecryption()
        {
            Console.WriteLine(Environment.NewLine + "Type DB Profile Text to Decrypt (Base 64 string )");
            string textToDecrypt = Console.ReadLine();
            var response = converter.Decrypt(textToDecrypt); 
            return response;
        }

        /// <summary>
        /// (First or One tme Activity) Generate CpiherText base 64 string to be saved in KV as encryptedKey secret
        /// </summary>
        /// <returns></returns>
        static string GetCipherTextString()
        {
            var cryptographyClient = InitializeCrypto();
            Console.WriteLine(Environment.NewLine + "Type a 32 byte string to create CiphereText KV Secret");
            string textToCipher = Console.ReadLine();
            var dbencryptkeytext = Convert.FromBase64String(textToCipher); 
            EncryptResult e = cryptographyClient.Encrypt(EncryptionAlgorithm.RsaOaep256, dbencryptkeytext);
            var encryptedbyteText = Convert.ToBase64String(e.Ciphertext);
            return encryptedbyteText;
        }

        /// <summary>
        /// Conects to KV , fetches identifier and Initializes crytographyclient object 
        /// </summary>
        /// <returns></returns>
        private static CryptographyClient InitializeCrypto()
        {
            try
            {   //Connect to KV , use Key to create and Initailise Crytography object 
                var keyVaultKeyIdentifier = new KeyVaultKeyIdentifier(new Uri(ConfigurationManager.AppSettings["KV_Key_KeyIdentifier"].ToString()));
                var credential = new DefaultAzureCredential(); //use default credentials (can use Azure AD app reg client/secret also to connect to keyvault)
                var keyClient = new KeyClient(keyVaultKeyIdentifier.VaultUri, credential);
                var keyVaultKey = keyClient.GetKey(keyVaultKeyIdentifier.Name).Value;
                var cryptographyClient = keyClient.GetCryptographyClient(keyVaultKey.Name, keyVaultKey.Properties.Version);
                return cryptographyClient;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw ex;
            }

        }
        private static async Task<StringEncryptor> GetEncryptorDecryptor(CryptographyClient cryptographyClient)
        {
            try
            {

                //Create AESCipher oject from KVSecretValues and Get Encryptdecrypt Converter object (StringEncryptor) ready            
                var keyVaultKeyIdentifier = new KeyVaultKeyIdentifier(new Uri(ConfigurationManager.AppSettings["KV_Key_KeyIdentifier"].ToString()));
                var credential = new DefaultAzureCredential();
                var secretclient = new SecretClient(keyVaultKeyIdentifier.VaultUri, credential);

                var encryptedKey = await secretclient.GetSecretAsync(ConfigurationManager.AppSettings["KV_Secret_EncryptedKeyName"].ToString());
                var KV_Secret_EncryptedKey = ((KeyVaultSecret)encryptedKey).Value; 
                var initializationVector = await secretclient.GetSecretAsync(ConfigurationManager.AppSettings["KV_Secret_InitializationVectorName"].ToString());
                var KV_Secret_InitializationVector = ((KeyVaultSecret)initializationVector).Value; 
                var encryptedSecretByte = Convert.FromBase64String(KV_Secret_EncryptedKey);
                DecryptResult decryptResult = cryptographyClient.Decrypt(EncryptionAlgorithm.RsaOaep256, encryptedSecretByte);
                var unencryptedKey = Convert.ToBase64String(decryptResult.Plaintext);

                ICipher cipher = new AesCipher(Convert.FromBase64String(unencryptedKey), Convert.FromBase64String(KV_Secret_InitializationVector));
                var converter = new StringEncryptor(cipher);
                return converter;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw ex;
            }

        }
    }

}


