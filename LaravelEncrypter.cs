using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace laravelEncrypter
{
    public class Encrypter
    {
        private string appKey;
        public Encrypter(string appKey){
            this.appKey = appKey;
        }
        public string encrypt(string content)
        {
            // Encrypt token content
            Rijndael myRijndael = Rijndael.Create();
            myRijndael.GenerateIV();
            byte[] key = Convert.FromBase64String(this.appKey);
            string iv = Convert.ToBase64String(myRijndael.IV);
            string value = Convert.ToBase64String(EncryptStringToBytes(content, key, myRijndael.IV));

            // Caculate mac with SHA256 Hash
            Byte[] hashBytes = new HMACSHA256(key).ComputeHash(Encoding.UTF8.GetBytes(iv+value));
            string mac = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

            Credential credential = new Credential(iv, value, mac);

            // Build token with Json
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(credential)));
        }

        public string decrypt(string token)
        {
            Credential credential = JsonConvert.DeserializeObject<Credential>(Encoding.UTF8.GetString(Convert.FromBase64String(token)));
            byte[] iv = Convert.FromBase64String(credential.iv);
            byte[] value = Convert.FromBase64String(credential.value);
            byte[] key = Convert.FromBase64String(this.appKey);

            return DecryptStringFromBytes(value, key, iv);            
        }

        private byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption. 
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream. 
            return encrypted;

        }

        private string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an RijndaelManaged object
            // with the specified key and IV.
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

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
    }

    class Credential
    {
        public string iv;
        public string value;
        public string mac;
        
        
        public Credential(string iv, string value, string mac) {
            this.iv = iv;
            this.value = value;
            this.mac = mac;  
        }
    }    
}
