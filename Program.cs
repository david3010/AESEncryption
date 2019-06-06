using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1
{
    class Program
    {
        public static void main()
        {
            string password = "password to encrypt";
            var Encrypted = AESEncryption.Encrypt(password, "Encryption");
            Console.WriteLine("Password Encrypted: " + Encrypted);
            var Decrypted = AESEncryption.Decrypt(Encrypted, "Encryption");
            Console.WriteLine("Password Decrypted: " + Decrypted);

            Console.ReadLine();
        }

        public class AESEncryption
        {
            private static int _iterations = 2;
            private static int _keySize = 256;

            private static string _hash = "SHA1";
            private static string _salt = "aselrias38490a32"; // Random
            private static string _vector = "8947az34awl34kjq"; // Random

            public static string Encrypt(string value, string password)
            {
                return Encrypt<AesManaged>(value, password);
            }

            public static string Encrypt<T>(string value, string password)
                    where T : SymmetricAlgorithm, new()
            {
                var vectorBytes = Encoding.ASCII.GetBytes(_vector);
                var saltBytes = Encoding.ASCII.GetBytes(_salt);
                var valueBytes = Encoding.ASCII.GetBytes(value);

                byte[] encrypted;
                using (T cipher = new T())
                {
                    using (PasswordDeriveBytes _passwordBytes =
                        new PasswordDeriveBytes(password, saltBytes, _hash, _iterations))
                    {
                        var keyBytes = _passwordBytes.GetBytes(_keySize / 8);

                        cipher.Mode = CipherMode.CBC;

                        using (ICryptoTransform encryptor = cipher.CreateEncryptor(keyBytes, vectorBytes))
                        {
                            using (MemoryStream to = new MemoryStream())
                            {
                                using (CryptoStream writer = new CryptoStream(to, encryptor, CryptoStreamMode.Write))
                                {
                                    writer.Write(valueBytes, 0, valueBytes.Length);
                                    writer.FlushFinalBlock();
                                    encrypted = to.ToArray();
                                }
                            }
                        }
                        cipher.Clear();
                    }
                }
                return Convert.ToBase64String(encrypted);
            }

            public static string Decrypt(string value, string password)
            {
                return Decrypt<AesManaged>(value, password);
            }

            public static string Decrypt<T>(string value, string password) where T : SymmetricAlgorithm, new()
            {
                var vectorBytes = Encoding.ASCII.GetBytes(_vector);
                var saltBytes = Encoding.ASCII.GetBytes(_salt);
                var valueBytes = Convert.FromBase64String(value);

                byte[] decrypted;
                int decryptedByteCount = 0;

                using (T cipher = new T())
                {
                    using (var _passwordBytes = new PasswordDeriveBytes(password, saltBytes, _hash, _iterations))
                    {
                        var keyBytes = _passwordBytes.GetBytes(_keySize / 8);

                        cipher.Mode = CipherMode.CBC;

                        try
                        {
                            using (ICryptoTransform decryptor = cipher.CreateDecryptor(keyBytes, vectorBytes))
                            {
                                using (MemoryStream from = new MemoryStream(valueBytes))
                                {
                                    using (CryptoStream reader = new CryptoStream(from, decryptor, CryptoStreamMode.Read))
                                    {
                                        decrypted = new byte[valueBytes.Length];
                                        decryptedByteCount = reader.Read(decrypted, 0, decrypted.Length);
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {

                            return String.Empty;
                        }

                        cipher.Clear();
                    }
                }
                return Encoding.UTF8.GetString(decrypted, 0, decryptedByteCount);
            }
        }
    }
}
